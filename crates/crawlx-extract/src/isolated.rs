//! Process-isolated page extraction: wire protocol, helper entry and local execution.
//!
//! Page parsing allocates through third-party parsers that cannot refuse an allocation part
//! way. Admission (`parse_budget`) bounds that for ordinary pages; this module is the answer for
//! the rest: a page that is too large for in-process admission, or that arrives while the shared
//! budget is under pressure, is parsed by a short-lived helper process whose own resource limits
//! (address space, CPU time, open files, processes, file size, core size) bound the damage. The
//! parent survives every helper failure and reports a typed [`IsolatedError`].
//!
//! # Layout
//!
//! * [`extract_local`] is the single extraction implementation. The parent calls it in-process
//!   and the helper calls it after decoding the request, so both routes produce identical
//!   documents.
//! * [`dispatch`] is the helper entry. The binary calls it first thing in `main`, before the
//!   async runtime or any argument parser exists. It is synchronous and applies the resource
//!   limits (safe `setrlimit` through `rustix`, no `unsafe`, no `pre_exec`) before it reads the
//!   request.
//! * [`encode_request_header`], [`encode_upload_request_header`], [`parse_response_stream`] and
//!   [`rebind_dedupe`] are the parent side of the wire.
//!
//! # Wire protocol (version 1)
//!
//! Request on the helper's standard input: [`REQUEST_MAGIC`], a little-endian `u32` header
//! length, the JSON header (`version`, `bodyLen` and a `task`: a page extraction with the
//! versioned options transport, secret values, optional dedupe snapshot and language stage, or an
//! HTML upload parse), then exactly `bodyLen` raw body bytes. Response on standard output:
//! [`RESPONSE_MAGIC`], a little-endian `u64` payload length, then JSON `page`, `need_language`,
//! `upload` or `err` (see [`Reply`] and [`Failure`]). The parent skips a bounded preamble before the
//! response magic, so stray output from a launcher cannot corrupt the frame. An exit status of
//! zero means a frame was delivered (a typed failure is still a frame); anything else is an
//! abnormal helper.
//!
//! # Options transport
//!
//! [`ExtractOptions`] is not serializable as a whole. The header carries a field-by-field
//! transport of every serializable field, and `options_to_transport` destructures the options
//! exhaustively, so a new field cannot be added without choosing how it crosses the boundary.
//! Compiled custom-field patterns travel as their source and are recompiled under the same
//! bounds. The scoped dedupe cache crosses as a hash-only snapshot
//! ([`crate::dedupe::DedupeSnapshotTransportV1`]); the helper records nothing, it returns the
//! commit observations and the parent rebinds them to the original handle
//! ([`crate::dedupe::DedupeHandle::attach_commit`]), so the shared cache changes only when the
//! caller commits the page. The trusted language detector stays in the parent: the helper
//! captures the text the native pipeline would classify, the parent runs the original detector
//! once and a second helper run replays the digest-bound answer (see
//! [`crate::isolated_language`]).
//!
//! # Uploads
//!
//! [`parse_upload_local`] is the HTML document-upload task (`parse::parse_document_with` for an
//! HTML file). The helper runs the same function and the parent rebuilds the identical
//! [`crate::parse::ParsedDocument`]. Other upload formats are refused as unsupported here.
//!
//! # Secrets
//!
//! Native content extraction applies a worker-injected privacy projection before article
//! NLP and digests. [`IsolatedSecrets`] carries the literal values that projection needs. It is
//! bounded, charged against a byte budget before its strings are allocated, and its `Debug`
//! never prints a value. The helper runs the same projection code as the in-process route. The
//! helper environment is cleared; secrets reach it only through the request frame.
//!
//! # Memory accounting
//!
//! A helper's `RLIMIT_AS` bounds that helper only. The parent charges the request frame, the
//! raw response and a conservative decode cost ([`response_decode_cost`]) before it builds a
//! document, but `slots x address space` of helpers can still exceed an operator's container
//! limit; the worker caps the concurrent helper count from the shared budget and exposes the
//! aggregate address-space ceiling.

use std::cell::Cell;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use crawlx_core::acquisition::{ValidationContextV1, ValidationPolicyV1};
use crawlx_core::config::{CustomField as CustomFieldSpec, JavascriptMode};
use crawlx_core::extraction::{ExtractionPolicyV1, ParserPipelineV1};
use crawlx_core::hash::Digest;
use crawlx_core::parser_memory::{ByteAdmissionError, ByteBudget, BytePermit};
use crawlx_core::scrape::AttributeSelector;
use crawlx_core::secret::Redactor;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::content_outputs::ContentOutputOptions;
use crate::custom_fields::CustomField;
use crate::decode::{DecodeOptions, MarkupRetention};
use crate::dedupe::{DedupeCommitEnvelopeV1, DedupeSnapshotTransportV1};
use crate::isolated_language::{
    LanguageBridgeError, LanguageCallV1, LanguageCapture, LanguageReplay, LanguageReplyV1,
};
use crate::parse::redact::{RedactEntity, RedactMode, RedactOptions, ReplaceStyle};
use crate::parse::{ParseError, ParseFormat, ParseLimits, ParseOptions, ParsedDocument};
use crate::parse_budget::ParseBudgetExhausted;
use crate::pipeline::{ParserPipeline, PipelineContent, PipelineError, PipelineInput};
use crate::{Document, ExtractError, ExtractOptions, Extractor, RAW_HTML_DOMAIN};

/// First argument of the helper process, after the program name.
pub const HELPER_SUBCOMMAND: &str = "__isolated-parse";

/// Protocol version carried in the request header.
pub const PROTOCOL_VERSION: u32 = 1;

/// Magic bytes opening a request frame.
pub const REQUEST_MAGIC: [u8; 8] = *b"\0CXISOQ\x01";

/// Magic bytes opening a response frame.
pub const RESPONSE_MAGIC: [u8; 8] = *b"\0CXISOR\x01";

/// Largest request header the helper accepts, in bytes (a dedupe snapshot is the largest part;
/// the request limit of [`HelperLimits`] applies on top).
pub const MAX_HEADER_BYTES: usize = 100 * 1024 * 1024;

/// Largest run of bytes the parent skips before the response magic.
pub const MAX_PREAMBLE_BYTES: usize = 4096;

/// Most secret values one request may carry.
pub const MAX_SECRET_VALUES: usize = 1024;

/// Most secret bytes one request may carry in total.
pub const MAX_SECRET_BYTES: usize = 1024 * 1024;

/// Conservative parent bytes charged per JSON value of a helper response (see
/// [`response_decode_cost`]).
pub const DECODE_BYTES_PER_JSON_VALUE: usize = 1024;

/// Helper exit status: a response frame was written (it may hold a typed failure).
pub const EXIT_OK: u8 = 0;

/// Helper exit status: the command line was malformed.
pub const EXIT_USAGE: u8 = 2;

/// Helper exit status: the resource limits could not be applied; nothing was read.
pub const EXIT_LIMITS: u8 = 3;

/// Helper exit status: the response could not be written.
pub const EXIT_IO: u8 = 4;

const MIN_ADDRESS_SPACE_BYTES: u64 = 64 * 1024 * 1024;
const MIN_FRAME_BYTES: u64 = 256;
const MAX_FRAME_BYTES: u64 = 1 << 30;
const MAX_CPU_SECONDS: u64 = 3600;
const HELPER_MAX_OPEN_FILES: u64 = 16;

/// Resource limits of one helper process.
///
/// The three parent-visible limits are passed on the helper command line; the helper applies the
/// address-space and CPU limits to itself before it reads a byte of the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HelperLimits {
    /// `RLIMIT_AS`: virtual address space of the helper. Allocation failure inside the helper
    /// aborts only the helper.
    pub address_space_bytes: u64,
    /// `RLIMIT_CPU`: CPU seconds before the helper is signalled (hard limit one second later).
    pub cpu_seconds: u64,
    /// Largest request frame (header plus body) the helper reads and the parent sends.
    pub max_request_bytes: u64,
    /// Largest response payload the helper writes and the parent reads.
    pub max_response_bytes: u64,
}

impl Default for HelperLimits {
    fn default() -> Self {
        Self {
            address_space_bytes: 512 * 1024 * 1024,
            cpu_seconds: 10,
            max_request_bytes: 32 * 1024 * 1024,
            max_response_bytes: 64 * 1024 * 1024,
        }
    }
}

impl HelperLimits {
    /// Check that every limit is inside its supported range.
    ///
    /// # Errors
    /// [`IsolatedError::Invalid`] naming the offending field.
    pub fn validate(&self) -> Result<(), IsolatedError> {
        let invalid = |field: &'static str, reason: &str| IsolatedError::Invalid {
            field,
            reason: reason.to_owned(),
        };
        if self.address_space_bytes < MIN_ADDRESS_SPACE_BYTES {
            return Err(invalid("addressSpaceBytes", "below the 64 MiB minimum"));
        }
        if !(1..=MAX_CPU_SECONDS).contains(&self.cpu_seconds) {
            return Err(invalid("cpuSeconds", "must be between 1 and 3600"));
        }
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&self.max_request_bytes) {
            return Err(invalid("maxRequestBytes", "must be between 256 bytes and 1 GiB"));
        }
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&self.max_response_bytes) {
            return Err(invalid("maxResponseBytes", "must be between 256 bytes and 1 GiB"));
        }
        Ok(())
    }

    /// The helper command line, starting with [`HELPER_SUBCOMMAND`].
    #[must_use]
    pub fn helper_args(&self) -> Vec<OsString> {
        vec![
            OsString::from(HELPER_SUBCOMMAND),
            OsString::from("--address-space-bytes"),
            OsString::from(self.address_space_bytes.to_string()),
            OsString::from("--cpu-seconds"),
            OsString::from(self.cpu_seconds.to_string()),
            OsString::from("--max-request-bytes"),
            OsString::from(self.max_request_bytes.to_string()),
            OsString::from("--max-response-bytes"),
            OsString::from(self.max_response_bytes.to_string()),
        ]
    }

    fn from_args(args: impl Iterator<Item = OsString>) -> Option<Self> {
        let mut address_space = None;
        let mut cpu = None;
        let mut request = None;
        let mut response = None;
        let mut args = args;
        while let Some(flag) = args.next() {
            let value = args.next()?.into_string().ok()?.parse::<u64>().ok()?;
            let slot = match flag.to_str()? {
                "--address-space-bytes" => &mut address_space,
                "--cpu-seconds" => &mut cpu,
                "--max-request-bytes" => &mut request,
                "--max-response-bytes" => &mut response,
                _ => return None,
            };
            if slot.replace(value).is_some() {
                return None;
            }
        }
        Some(Self {
            address_space_bytes: address_space?,
            cpu_seconds: cpu?,
            max_request_bytes: request?,
            max_response_bytes: response?,
        })
    }
}

/// Which extraction entry point runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Engine {
    /// The shared versioned parser pipeline with its default specification and a `text/html`
    /// page route: what acquisition runs.
    #[default]
    Pipeline,
    /// [`Extractor::extract_bytes`] / [`Extractor::extract_bytes_with_projection`] directly.
    Extractor,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretValues {
    request: Vec<String>,
    captcha: Option<Vec<String>>,
    #[serde(skip)]
    permit: Option<BytePermit>,
}

/// Secret literals needed by the privacy projection, never printed.
///
/// `request` holds header and cookie values of the request; `captcha`, when present, holds the
/// live provider registry in the registry's own order (longest first) and switches on the
/// strict (fail-closed on invalid UTF-8) projection used when a registry exists.
///
/// The strings are charged against a [`ByteBudget`] before they are copied, and the reservation
/// lives as long as the longest holder of this handle (clones share one allocation).
#[derive(Clone, Default)]
pub struct IsolatedSecrets {
    values: Arc<SecretValues>,
}

impl Serialize for IsolatedSecrets {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.values.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IsolatedSecrets {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        SecretValues::deserialize(deserializer).map(|values| Self {
            values: Arc::new(values),
        })
    }
}

impl PartialEq for IsolatedSecrets {
    fn eq(&self, other: &Self) -> bool {
        self.values.request == other.values.request && self.values.captcha == other.values.captcha
    }
}

impl Eq for IsolatedSecrets {}

impl std::fmt::Debug for IsolatedSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsolatedSecrets")
            .field("request_values", &self.values.request.len())
            .field("captcha_values", &self.values.captcha.as_ref().map(Vec::len))
            .field(
                "reserved_bytes",
                &self.values.permit.as_ref().map(BytePermit::bytes),
            )
            .finish()
    }
}

/// Collect at most [`MAX_SECRET_VALUES`]` + 1` non-empty values, so an unbounded iterator cannot
/// force an unbounded allocation before the bounds are checked.
fn bounded_values<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    values
        .into_iter()
        .filter(|value| !value.is_empty())
        .take(MAX_SECRET_VALUES + 1)
        .collect()
}

impl IsolatedSecrets {
    /// Request secrets (`RequestControls::secret_values`) plus the live provider registry values
    /// (longest first, as `CaptchaSecrets::literal_snapshot_admitted` returns them), charged against the
    /// process-wide budget. Empty values are dropped. This is the strict projection of
    /// acquisition with a registry present: an empty registry still fails closed on text that is
    /// not valid UTF-8.
    ///
    /// # Errors
    /// [`IsolatedError::Invalid`] when the bounds of [`MAX_SECRET_VALUES`] or
    /// [`MAX_SECRET_BYTES`] are exceeded, [`IsolatedError::Admission`] when the budget refuses
    /// the copy.
    pub fn new<'a, 'b>(
        request: impl IntoIterator<Item = &'a str>,
        captcha: impl IntoIterator<Item = &'b str>,
    ) -> Result<Self, IsolatedError> {
        Self::new_in(crawlx_core::parser_memory::global(), request, Some(captcha))
    }

    /// Request secrets only: the lossy projection used when no provider registry exists.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn request_only<'a>(request: impl IntoIterator<Item = &'a str>) -> Result<Self, IsolatedError> {
        Self::new_in(
            crawlx_core::parser_memory::global(),
            request,
            None::<std::iter::Empty<&str>>,
        )
    }

    /// [`Self::new`] and [`Self::request_only`] against an explicit budget (`captcha` of `None`
    /// selects the lossy projection).
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn new_in<'a, 'b>(
        budget: &Arc<ByteBudget>,
        request: impl IntoIterator<Item = &'a str>,
        captcha: Option<impl IntoIterator<Item = &'b str>>,
    ) -> Result<Self, IsolatedError> {
        let request = bounded_values(request);
        let captcha = captcha.map(bounded_values);
        let captcha_values: &[&str] = captcha.as_deref().unwrap_or_default();
        let count = request.len().saturating_add(captcha_values.len());
        let bytes = request
            .iter()
            .chain(captcha_values)
            .fold(0_usize, |total, value| total.saturating_add(value.len()));
        if count > MAX_SECRET_VALUES || bytes > MAX_SECRET_BYTES {
            return Err(IsolatedError::Invalid {
                field: "secrets",
                reason: format!("{count} values, {bytes} bytes exceed the transport bounds"),
            });
        }
        // Heap bytes of the copies: string payloads plus one `String` header per value, with
        // headroom for the vectors' own growth.
        let headers =
            count
                .checked_mul(std::mem::size_of::<String>() * 2)
                .ok_or(IsolatedError::LimitExceeded {
                    what: "secret values",
                    limit: widen(MAX_SECRET_VALUES),
                })?;
        let permit = budget.try_reserve(bytes.saturating_add(headers))?;
        let own = |values: &[&str]| -> Result<Vec<String>, IsolatedError> {
            let mut out = Vec::new();
            out.try_reserve_exact(values.len())
                .map_err(|_| IsolatedError::LimitExceeded {
                    what: "secret values",
                    limit: widen(MAX_SECRET_VALUES),
                })?;
            out.extend(values.iter().map(|value| (*value).to_owned()));
            Ok(out)
        };
        Ok(Self {
            values: Arc::new(SecretValues {
                request: own(&request)?,
                captcha: captcha.as_deref().map(own).transpose()?,
                permit: Some(permit),
            }),
        })
    }

    /// No secret value is carried.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.request.is_empty() && self.values.captcha.as_ref().is_none_or(Vec::is_empty)
    }

    fn request(&self) -> impl Iterator<Item = &str> {
        self.values.request.iter().map(String::as_str)
    }

    fn captcha(&self) -> Option<&[String]> {
        self.values.captcha.as_deref()
    }

    fn check_bounds(&self) -> Result<(), IsolatedError> {
        let captcha = self.values.captcha.as_deref().unwrap_or_default();
        let count = self.values.request.len().saturating_add(captcha.len());
        let bytes = self
            .values
            .request
            .iter()
            .chain(captcha)
            .fold(0_usize, |total, value| total.saturating_add(value.len()));
        if count > MAX_SECRET_VALUES || bytes > MAX_SECRET_BYTES {
            return Err(IsolatedError::Invalid {
                field: "secrets",
                reason: format!("{count} values, {bytes} bytes exceed the transport bounds"),
            });
        }
        Ok(())
    }
}

/// A typed refusal produced by the helper (or by the same code in-process).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Failure {
    /// A parse limit refused the input.
    #[error("{what} {actual} exceeds limit {limit}")]
    TooLarge {
        /// Which limit.
        what: String,
        /// Configured limit.
        limit: u64,
        /// Observed value.
        actual: u64,
    },
    /// A selector option did not parse.
    #[error("invalid selector `{selector}`: {reason}")]
    InvalidSelector {
        /// The offending selector.
        selector: String,
        /// Parser message.
        reason: String,
    },
    /// The options, policy or document were refused; the message is the extractor's.
    #[error("{message}")]
    Rejected {
        /// Extractor message.
        message: String,
    },
    /// The helper's own parse-memory budget refused the parse.
    #[error("parse memory budget exhausted: requested {requested} bytes, {available} of {limit} available")]
    ParseMemory {
        /// Bytes asked for.
        requested: u64,
        /// Bytes free.
        available: u64,
        /// Budget size.
        limit: u64,
    },
    /// The helper could not allocate a bounded buffer for the request.
    #[error("helper could not allocate {what}")]
    Resource {
        /// What was being allocated.
        what: String,
    },
    /// The serialized result is larger than the response limit.
    #[error("serialized result {actual} exceeds response limit {limit}")]
    OutputTooLarge {
        /// Response limit.
        limit: u64,
        /// Serialized size.
        actual: u64,
    },
    /// The request frame was malformed or of another protocol version.
    #[error("malformed request: {message}")]
    Protocol {
        /// What was wrong.
        message: String,
    },
    /// The dedupe snapshot or the language exchange of the request was refused.
    #[error("bridge refused: {message}")]
    Bridge {
        /// Finite classification, never document content.
        message: String,
    },
    /// An upload parse was refused with a message of the parser (never document content).
    #[error("{message}")]
    Upload {
        /// Parser message.
        message: String,
    },
    /// The upload is not HTML, which is the only format the helper serves.
    #[error("isolated upload parsing supports HTML only")]
    UploadFormat,
}

impl From<&ParseError> for Failure {
    fn from(error: &ParseError) -> Self {
        match error {
            ParseError::TooLarge { what, limit, actual } => Self::TooLarge {
                what: (*what).to_owned(),
                limit: widen(*limit),
                actual: widen(*actual),
            },
            ParseError::InvalidSelector { selector, reason } => Self::InvalidSelector {
                selector: selector.clone(),
                reason: reason.clone(),
            },
            ParseError::ParseMemory(exhausted) => Self::ParseMemory {
                requested: widen(exhausted.requested),
                available: widen(exhausted.available),
                limit: widen(exhausted.limit),
            },
            other => Self::Upload {
                message: other.to_string(),
            },
        }
    }
}

impl From<&ExtractError> for Failure {
    fn from(error: &ExtractError) -> Self {
        match error {
            ExtractError::TooLarge { what, limit, actual } => Self::TooLarge {
                what: (*what).to_owned(),
                limit: widen(*limit),
                actual: widen(*actual),
            },
            ExtractError::InvalidSelector { selector, reason } => Self::InvalidSelector {
                selector: selector.clone(),
                reason: reason.clone(),
            },
            ExtractError::ParseMemory(exhausted) => Self::ParseMemory {
                requested: widen(exhausted.requested),
                available: widen(exhausted.available),
                limit: widen(exhausted.limit),
            },
            other => Self::Rejected {
                message: other.to_string(),
            },
        }
    }
}

/// Why an isolated or admitted extraction did not produce a document.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IsolatedError {
    /// The request needs a capability the isolated parser does not provide.
    #[error("isolated parsing does not support {capability}")]
    Unsupported {
        /// The unsupported capability (`non-HTML upload`).
        capability: &'static str,
    },
    /// A request, limit or secret value is outside the supported bounds.
    #[error("invalid isolated parser {field}: {reason}")]
    Invalid {
        /// The offending field.
        field: &'static str,
        /// Why it was refused.
        reason: String,
    },
    /// The parent could not admit the bytes the exchange needs.
    #[error("isolated parser admission refused")]
    Admission(#[from] ByteAdmissionError),
    /// A size bound of the exchange was exceeded.
    #[error("isolated parser {what} exceeds limit {limit}")]
    LimitExceeded {
        /// Which bound.
        what: &'static str,
        /// The limit.
        limit: u64,
    },
    /// The helper did not finish before the wall-clock deadline and was killed.
    #[error("isolated parser timed out after {timeout:?}")]
    Timeout {
        /// The deadline.
        timeout: Duration,
    },
    /// The caller cancelled; the helper was killed and reaped.
    #[error("isolated parser cancelled")]
    Cancelled,
    /// The helper was ended by a signal (memory, CPU or file limit, abort, kill).
    #[error("isolated parser terminated by signal {signal}")]
    Signal {
        /// Signal number.
        signal: i32,
    },
    /// The helper exited with a nonzero status.
    #[error("isolated parser exited with status {code}")]
    Exit {
        /// Exit status.
        code: i32,
    },
    /// The helper process could not be started.
    #[error("isolated parser could not be started")]
    Spawn(#[source] std::io::Error),
    /// Talking to the helper failed.
    #[error("isolated parser {stage} failed")]
    Io {
        /// Which step failed.
        stage: &'static str,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The helper broke the wire protocol.
    #[error("isolated parser protocol violation: {reason}")]
    Protocol {
        /// What was wrong.
        reason: String,
    },
    /// The helper delivered a typed refusal.
    #[error("isolated parser refused the input")]
    Rejected(#[from] Failure),
    /// The in-process extractor delivered a typed error. Boxed: [`ExtractError`] itself can
    /// carry an [`IsolatedError`].
    #[error("extraction failed")]
    Extract(#[source] Box<ExtractError>),
    /// The in-process document parser delivered a typed error (boxed: [`ParseError`] can carry
    /// an [`IsolatedError`]).
    #[error("document parse failed")]
    Parse(#[source] Box<ParseError>),
    /// The dedupe snapshot could not be exported or the helper's commit did not match the
    /// parent's expectation.
    #[error("dedupe transport refused")]
    Dedupe(#[source] crate::dedupe::DedupeTransportError),
    /// The language exchange was refused.
    #[error("language exchange refused")]
    Language(#[from] LanguageBridgeError),
    /// The blocking task carrying the in-process parse failed.
    #[error("admitted parser task failed")]
    Task(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl From<ParseError> for IsolatedError {
    fn from(error: ParseError) -> Self {
        Self::Parse(Box::new(error))
    }
}

impl From<ExtractError> for IsolatedError {
    fn from(error: ExtractError) -> Self {
        Self::Extract(Box::new(error))
    }
}

impl IsolatedError {
    /// The failure is resource exhaustion rather than a verdict on the document: admission or
    /// size bounds, the wall-clock deadline, a limit signal (`SIGABRT`, `SIGKILL`, `SIGSEGV`,
    /// `SIGXCPU`, `SIGXFSZ`) or a helper-side resource refusal.
    #[must_use]
    pub fn is_resource_exhausted(&self) -> bool {
        match self {
            Self::Admission(_) | Self::LimitExceeded { .. } | Self::Timeout { .. } => true,
            Self::Signal { signal } => matches!(signal, 6 | 9 | 11 | 24 | 25),
            Self::Rejected(
                Failure::ParseMemory { .. } | Failure::Resource { .. } | Failure::OutputTooLarge { .. },
            ) => true,
            Self::Extract(error) => matches!(**error, ExtractError::ParseMemory(_)),
            Self::Language(error) => matches!(
                error,
                LanguageBridgeError::Budget(_)
                    | LanguageBridgeError::Allocation
                    | LanguageBridgeError::TextTooLarge
            ),
            Self::Parse(error) => matches!(
                **error,
                ParseError::ParseMemory(_) | ParseError::ResourceExhausted { .. }
            ),
            _ => false,
        }
    }

    /// Convert for callers that report [`ExtractError`]. Resource exhaustion becomes
    /// [`ExtractError::ParseMemory`] (a page that exhausts an isolated process exceeds every
    /// budget, so `exceeds_budget` is true); other failures keep their typed form or become an
    /// invalid-policy error carrying the message.
    #[must_use]
    pub fn into_extract_error(self) -> ExtractError {
        match self {
            Self::Extract(error) => *error,
            Self::Admission(error) => ExtractError::ParseMemory(ParseBudgetExhausted {
                requested: error.requested,
                available: error.available,
                limit: error.limit,
            }),
            Self::Rejected(Failure::TooLarge { what, limit, actual }) => ExtractError::TooLarge {
                what: static_limit_name(&what),
                limit: narrow(limit),
                actual: narrow(actual),
            },
            Self::Rejected(Failure::InvalidSelector { selector, reason }) => {
                ExtractError::InvalidSelector { selector, reason }
            }
            Self::Rejected(Failure::ParseMemory {
                requested,
                available,
                limit,
            }) => ExtractError::ParseMemory(ParseBudgetExhausted {
                requested: narrow(requested),
                available: narrow(available),
                limit: narrow(limit),
            }),
            other if other.is_resource_exhausted() => ExtractError::ParseMemory(ParseBudgetExhausted {
                requested: usize::MAX,
                available: 0,
                limit: 0,
            }),
            other => ExtractError::Isolated(other),
        }
    }

    /// Convert for callers that report [`crate::parse::ParseError`]. Resource exhaustion becomes
    /// [`crate::parse::ParseError::ResourceExhausted`] with a finite classification (never
    /// document content); every other failure is carried as
    /// [`crate::parse::ParseError::Isolated`].
    #[must_use]
    pub fn into_parse_error(self) -> ParseError {
        match self {
            Self::Parse(error) => *error,
            Self::Rejected(Failure::TooLarge { what, limit, actual }) => ParseError::TooLarge {
                what: static_limit_name(&what),
                limit: narrow(limit),
                actual: narrow(actual),
            },
            Self::Rejected(Failure::InvalidSelector { selector, reason }) => {
                ParseError::InvalidSelector { selector, reason }
            }
            Self::Rejected(Failure::ParseMemory {
                requested,
                available,
                limit,
            }) => ParseError::ParseMemory(ParseBudgetExhausted {
                requested: narrow(requested),
                available: narrow(available),
                limit: narrow(limit),
            }),
            other if other.is_resource_exhausted() => ParseError::ResourceExhausted {
                what: "isolated parser",
                detail: match other {
                    Self::Admission(_) => "admission refused",
                    Self::LimitExceeded { .. } => "size bound exceeded",
                    Self::Timeout { .. } => "deadline exceeded",
                    Self::Signal { .. } => "helper terminated by resource limit",
                    _ => "parser memory refused",
                }
                .to_owned(),
            },
            other => ParseError::Isolated(other),
        }
    }
}

fn widen(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn narrow(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn static_limit_name(name: &str) -> &'static str {
    const KNOWN: [&str; 14] = [
        "bytes",
        "nodes",
        "depth",
        "operations",
        "input bytes",
        "output bytes",
        "projected main characters",
        "projected comment characters",
        "text characters",
        "children",
        "uncompressed bytes",
        "archive entries",
        "decompressed stream bytes",
        "group depth",
    ];
    KNOWN
        .into_iter()
        .find(|known| *known == name)
        .unwrap_or("isolated limit")
}

// ---------------------------------------------------------------------------------------------
// Options transport
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ValidationTransport {
    policy: ValidationPolicyV1,
    target_status: Option<u16>,
    transport_succeeded: bool,
    truncated: bool,
    method_head: bool,
    cached_body_available: bool,
    policy_blocked: bool,
    cancelled: bool,
}

impl From<&ValidationContextV1> for ValidationTransport {
    fn from(context: &ValidationContextV1) -> Self {
        Self {
            policy: context.policy.clone(),
            target_status: context.target_status,
            transport_succeeded: context.transport_succeeded,
            truncated: context.truncated,
            method_head: context.method_head,
            cached_body_available: context.cached_body_available,
            policy_blocked: context.policy_blocked,
            cancelled: context.cancelled,
        }
    }
}

impl From<ValidationTransport> for ValidationContextV1 {
    fn from(transport: ValidationTransport) -> Self {
        let mut context = Self::default();
        context.policy = transport.policy;
        context.target_status = transport.target_status;
        context.transport_succeeded = transport.transport_succeeded;
        context.truncated = transport.truncated;
        context.method_head = transport.method_head;
        context.cached_body_available = transport.cached_body_available;
        context.policy_blocked = transport.policy_blocked;
        context.cancelled = transport.cancelled;
        context
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ModeTransport {
    Accurate,
    Aggressive,
    Fast,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StyleTransport {
    Tag,
    Mask,
    Remove,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RedactTransport {
    mode: ModeTransport,
    entities: Vec<String>,
    replace_style: StyleTransport,
}

impl From<&RedactOptions> for RedactTransport {
    fn from(options: &RedactOptions) -> Self {
        Self {
            mode: match options.mode {
                RedactMode::Accurate => ModeTransport::Accurate,
                RedactMode::Aggressive => ModeTransport::Aggressive,
                RedactMode::Fast => ModeTransport::Fast,
            },
            entities: options
                .entities
                .iter()
                .map(|entity| entity.name().to_owned())
                .collect(),
            replace_style: match options.replace_style {
                ReplaceStyle::Tag => StyleTransport::Tag,
                ReplaceStyle::Mask => StyleTransport::Mask,
                ReplaceStyle::Remove => StyleTransport::Remove,
            },
        }
    }
}

impl RedactTransport {
    fn into_options(self) -> Result<RedactOptions, Failure> {
        let mut entities = std::collections::BTreeSet::new();
        for name in &self.entities {
            let entity = RedactEntity::from_name(name).ok_or_else(|| Failure::Protocol {
                message: "unknown redaction entity".to_owned(),
            })?;
            entities.insert(entity);
        }
        Ok(RedactOptions {
            mode: match self.mode {
                ModeTransport::Accurate => RedactMode::Accurate,
                ModeTransport::Aggressive => RedactMode::Aggressive,
                ModeTransport::Fast => RedactMode::Fast,
            },
            entities,
            replace_style: match self.replace_style {
                StyleTransport::Tag => ReplaceStyle::Tag,
                StyleTransport::Mask => ReplaceStyle::Mask,
                StyleTransport::Remove => ReplaceStyle::Remove,
            },
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OptionsTransport {
    only_main_content: bool,
    include_tags: Vec<String>,
    exclude_tags: Vec<String>,
    max_input_bytes: u64,
    max_nodes: u64,
    status: u16,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    depth: u32,
    discover_endpoints: bool,
    javascript_mode: JavascriptMode,
    custom_fields: Vec<CustomFieldSpec>,
    forms: bool,
    page_type: bool,
    technologies: bool,
    keep_data_images: bool,
    content: Option<ExtractionPolicyV1>,
    acquisition_validation: Option<ValidationTransport>,
    image_references: bool,
    attribute_selectors: Vec<AttributeSelector>,
    content_redaction: Option<RedactTransport>,
    outputs: Option<ContentOutputOptions>,
    decode: Option<DecodeOptions>,
    markup: Option<MarkupRetention>,
}

fn options_to_transport(options: &ExtractOptions) -> Result<OptionsTransport, IsolatedError> {
    // Exhaustive on purpose: a new option must choose how it crosses the process boundary.
    let ExtractOptions {
        only_main_content,
        include_tags,
        exclude_tags,
        max_input_bytes,
        max_nodes,
        status,
        headers,
        content_type,
        depth,
        discover_endpoints,
        javascript_mode,
        custom_fields,
        forms,
        page_type,
        technologies,
        keep_data_images,
        content,
        acquisition_validation,
        image_references,
        attribute_selectors,
        content_redaction,
        language_detector: _,
        dedupe_cache: _,
        outputs,
        decode,
        markup,
    } = options;
    let mut specs = Vec::with_capacity(custom_fields.len());
    for field in custom_fields {
        specs.push(CustomFieldSpec {
            name: field.name.clone(),
            regex: field
                .regex
                .iter()
                .map(|regex| regex.as_str().to_owned())
                .collect(),
            part: field.part,
            group: u32::try_from(field.group).map_err(|_| IsolatedError::Invalid {
                field: "customFields.group",
                reason: "capture group does not fit u32".to_owned(),
            })?,
        });
    }
    Ok(OptionsTransport {
        only_main_content: *only_main_content,
        include_tags: include_tags.clone(),
        exclude_tags: exclude_tags.clone(),
        max_input_bytes: widen(*max_input_bytes),
        max_nodes: widen(*max_nodes),
        status: *status,
        headers: headers.clone(),
        content_type: content_type.clone(),
        depth: *depth,
        discover_endpoints: *discover_endpoints,
        javascript_mode: *javascript_mode,
        custom_fields: specs,
        forms: *forms,
        page_type: *page_type,
        technologies: *technologies,
        keep_data_images: *keep_data_images,
        content: content.clone(),
        acquisition_validation: acquisition_validation.as_ref().map(ValidationTransport::from),
        image_references: *image_references,
        attribute_selectors: attribute_selectors.clone(),
        content_redaction: content_redaction.as_ref().map(RedactTransport::from),
        outputs: outputs.clone(),
        decode: decode.clone(),
        markup: *markup,
    })
}

fn options_from_transport(transport: OptionsTransport) -> Result<ExtractOptions, Failure> {
    let custom_fields =
        CustomField::compile_all(&transport.custom_fields).map_err(|error| Failure::Rejected {
            message: error.to_string(),
        })?;
    let too_big = |what: &str| Failure::Protocol {
        message: format!("{what} does not fit this platform"),
    };
    Ok(ExtractOptions {
        only_main_content: transport.only_main_content,
        include_tags: transport.include_tags,
        exclude_tags: transport.exclude_tags,
        max_input_bytes: usize::try_from(transport.max_input_bytes).map_err(|_| too_big("maxInputBytes"))?,
        max_nodes: usize::try_from(transport.max_nodes).map_err(|_| too_big("maxNodes"))?,
        status: transport.status,
        headers: transport.headers,
        content_type: transport.content_type,
        depth: transport.depth,
        discover_endpoints: transport.discover_endpoints,
        javascript_mode: transport.javascript_mode,
        custom_fields,
        forms: transport.forms,
        page_type: transport.page_type,
        technologies: transport.technologies,
        keep_data_images: transport.keep_data_images,
        content: transport.content,
        acquisition_validation: transport.acquisition_validation.map(ValidationContextV1::from),
        image_references: transport.image_references,
        attribute_selectors: transport.attribute_selectors,
        content_redaction: transport
            .content_redaction
            .map(RedactTransport::into_options)
            .transpose()?,
        language_detector: None,
        dedupe_cache: None,
        outputs: transport.outputs,
        decode: transport.decode,
        markup: transport.markup,
    })
}

// ---------------------------------------------------------------------------------------------
// Local execution (parent in-process route and helper share it)
// ---------------------------------------------------------------------------------------------

fn pipeline() -> Result<&'static ParserPipeline, &'static PipelineError> {
    static PIPELINE: LazyLock<Result<ParserPipeline, PipelineError>> =
        LazyLock::new(|| ParserPipeline::new(ParserPipelineV1::default()));
    PIPELINE.as_ref()
}

type Projection<'a> = dyn Fn(&str) -> Option<String> + 'a;

fn pipeline_page(
    body: &[u8],
    base: &Url,
    options: &ExtractOptions,
    projection: Option<&Projection<'_>>,
) -> Result<Document, ExtractError> {
    let invalid = |reason: String| {
        ExtractError::InvalidContentPolicy(crawlx_core::CoreError::Invalid {
            field: "extract.pipeline",
            reason,
        })
    };
    let pipeline = pipeline().map_err(|error| invalid(error.to_string()))?;
    let mut input = PipelineInput::new(body)
        .with_page_url(base)
        .with_content_type("text/html")
        .with_page_options(options);
    if let Some(project) = projection {
        input = input.with_projection(project);
    }
    let output = pipeline.run(input).map_err(|error| match error {
        PipelineError::Extract(error) => error,
        PipelineError::Invalid(error) => ExtractError::InvalidContentPolicy(error),
        PipelineError::Limit { what, limit, actual } => ExtractError::TooLarge {
            what,
            limit: narrow(limit),
            actual: narrow(actual),
        },
        other => invalid(other.to_string()),
    })?;
    match output.content {
        PipelineContent::Page(document) => Ok(*document),
        _ => Err(invalid("page extraction requires an HTML route".to_owned())),
    }
}

fn run_engine(
    engine: Engine,
    body: &[u8],
    base: &Url,
    options: &ExtractOptions,
    projection: Option<&Projection<'_>>,
) -> Result<Document, ExtractError> {
    match (engine, projection) {
        (Engine::Pipeline, projection) => pipeline_page(body, base, options, projection),
        (Engine::Extractor, Some(project)) => {
            Extractor::extract_bytes_with_projection(body, base, options, project)
        }
        (Engine::Extractor, None) => Extractor::extract_bytes(body, base, options),
    }
}

fn privacy_unavailable() -> ExtractError {
    ExtractError::InvalidContentPolicy(crawlx_core::CoreError::Invalid {
        field: "extract.privacy",
        reason: "dynamic-secret projection unavailable".into(),
    })
}

fn replace_captcha(text: &str, values: &[String]) -> Option<String> {
    values.iter().any(|value| text.contains(value.as_str())).then(|| {
        values.iter().fold(text.to_owned(), |redacted, value| {
            redacted.replace(value.as_str(), "[REDACTED]")
        })
    })
}

/// Extract a page exactly as acquisition does, including the secret projection.
///
/// This is the one implementation behind both routes. Without a native content policy no
/// projection runs. With one, request secrets are scrubbed from the body first; the final
/// projection scrubs normalized text again and, when a provider registry is attached, replaces
/// its values by `[REDACTED]`, failing closed on text that is not valid UTF-8.
///
/// # Errors
/// The extractor's [`ExtractError`]; `extract.privacy` when the strict projection cannot be
/// applied.
pub fn extract_local(
    body: &[u8],
    base: &Url,
    options: &ExtractOptions,
    engine: Engine,
    secrets: &IsolatedSecrets,
) -> Result<Document, ExtractError> {
    if options.content.is_none() {
        return run_engine(engine, body, base, options, None);
    }
    let redactor = Redactor::new();
    let request = || secrets.request();
    let prepared = redactor.scrub_bytes(body, request());
    let Some(captcha) = secrets.captcha() else {
        let project = |text: &str| match redactor.scrub_bytes(text.as_bytes(), request()) {
            std::borrow::Cow::Borrowed(_) => None,
            std::borrow::Cow::Owned(scrubbed) => Some(match String::from_utf8(scrubbed) {
                Ok(text) => text,
                Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
            }),
        };
        return run_engine(engine, prepared.as_ref(), base, options, Some(&project));
    };
    let failed = Cell::new(false);
    let project = |text: &str| {
        let controlled = redactor.scrub_bytes(text.as_bytes(), request());
        let Ok(text) = std::str::from_utf8(controlled.as_ref()) else {
            failed.set(true);
            return Some(String::new());
        };
        match replace_captcha(text, captcha) {
            Some(value) => Some(value),
            None => match controlled {
                std::borrow::Cow::Borrowed(_) => None,
                std::borrow::Cow::Owned(bytes) => String::from_utf8(bytes).ok(),
            },
        }
    };
    let document = run_engine(engine, prepared.as_ref(), base, options, Some(&project));
    if failed.get() {
        return Err(privacy_unavailable());
    }
    document
}

/// The exact bytes [`extract_local`] hands to the extractor: the body itself, or under a native
/// content policy the body with the request secrets scrubbed. The raw-source digest of the
/// resulting document is taken over these bytes.
#[must_use]
pub fn prepared_body<'a>(
    body: &'a [u8],
    options: &ExtractOptions,
    secrets: &IsolatedSecrets,
) -> std::borrow::Cow<'a, [u8]> {
    if options.content.is_none() {
        return std::borrow::Cow::Borrowed(body);
    }
    Redactor::new().scrub_bytes(body, secrets.request())
}

/// Parse an HTML document upload exactly as the API does (`parse::parse_document_with`).
///
/// The parent runs this in process and the helper runs the same function, so both routes build
/// byte-identical documents. Only HTML is served; any other detected format is refused.
///
/// # Errors
/// [`IsolatedError::Unsupported`] for a non-HTML upload, [`IsolatedError::Parse`] for the
/// parser's own typed errors.
pub fn parse_upload_local(
    bytes: &[u8],
    filename: Option<&str>,
    content_type: Option<&str>,
    options: &ParseOptions,
) -> Result<ParsedDocument, IsolatedError> {
    let format = crate::parse::detect_format(bytes, filename, content_type, &options.limits)?;
    if format != ParseFormat::Html {
        return Err(IsolatedError::Unsupported {
            capability: "non-HTML upload",
        });
    }
    Ok(crate::parse::parse_document_with(
        bytes,
        filename,
        content_type,
        options,
    )?)
}

// ---------------------------------------------------------------------------------------------
// Wire: shared types
// ---------------------------------------------------------------------------------------------

/// Where the language detector stands in the two-pass exchange (see
/// [`crate::isolated_language`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", rename_all_fields = "camelCase")]
#[non_exhaustive]
pub enum LanguageStage {
    /// The options carry no detector.
    None,
    /// First pass: the helper installs a capturing detector with the original's bundle digest and
    /// reports the text the native pipeline would classify.
    Capture {
        /// Bundle digest of the parent's detector.
        bundle_digest: crawlx_core::hash::Digest,
    },
    /// Second pass: the helper replays the parent's digest-bound answer.
    Replay(LanguageReplyV1),
}

impl LanguageStage {
    /// The first pass for `options`: [`Self::Capture`] when a detector is present.
    #[must_use]
    pub fn first_pass(options: &ExtractOptions) -> Self {
        options
            .language_detector
            .as_ref()
            .map_or(Self::None, |handle| Self::Capture {
                bundle_digest: handle.detector().bundle_digest(),
            })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LimitsTransport {
    max_input_bytes: u64,
    max_uncompressed_bytes: u64,
    max_entries: u64,
    max_pages: u64,
    max_sheets: u64,
    max_rows: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UploadOptionsTransport {
    limits: LimitsTransport,
    only_main_content: bool,
    include_tags: Vec<String>,
    exclude_tags: Vec<String>,
}

impl UploadOptionsTransport {
    fn from_options(options: &ParseOptions) -> Self {
        let limits = &options.limits;
        Self {
            limits: LimitsTransport {
                max_input_bytes: widen(limits.max_input_bytes),
                max_uncompressed_bytes: widen(limits.max_uncompressed_bytes),
                max_entries: widen(limits.max_entries),
                max_pages: widen(limits.max_pages),
                max_sheets: widen(limits.max_sheets),
                max_rows: widen(limits.max_rows),
            },
            only_main_content: options.only_main_content,
            include_tags: options.include_tags.clone(),
            exclude_tags: options.exclude_tags.clone(),
        }
    }

    fn into_options(self) -> Result<ParseOptions, Failure> {
        let fit = |value: u64| {
            usize::try_from(value).map_err(|_| Failure::Protocol {
                message: "a limit does not fit this platform".to_owned(),
            })
        };
        Ok(ParseOptions {
            limits: ParseLimits {
                max_input_bytes: fit(self.limits.max_input_bytes)?,
                max_uncompressed_bytes: fit(self.limits.max_uncompressed_bytes)?,
                max_entries: fit(self.limits.max_entries)?,
                max_pages: fit(self.limits.max_pages)?,
                max_sheets: fit(self.limits.max_sheets)?,
                max_rows: fit(self.limits.max_rows)?,
            },
            only_main_content: self.only_main_content,
            include_tags: self.include_tags,
            exclude_tags: self.exclude_tags,
            ..ParseOptions::default()
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", rename_all_fields = "camelCase")]
enum Task {
    Page {
        engine: Engine,
        base_url: Url,
        options: Box<OptionsTransport>,
        secrets: Box<IsolatedSecrets>,
        dedupe: Option<Box<DedupeSnapshotTransportV1>>,
        language: Box<LanguageStage>,
    },
    UploadHtml {
        filename: Option<String>,
        content_type: Option<String>,
        options: UploadOptionsTransport,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Header {
    version: u32,
    body_len: u64,
    task: Task,
}

fn encode_header(body_len: usize, task: Task) -> Result<Vec<u8>, IsolatedError> {
    let header = Header {
        version: PROTOCOL_VERSION,
        body_len: widen(body_len),
        task,
    };
    let json = serde_json::to_vec(&header).map_err(|error| IsolatedError::Invalid {
        field: "options",
        reason: error.to_string(),
    })?;
    if json.len() > MAX_HEADER_BYTES {
        return Err(IsolatedError::LimitExceeded {
            what: "request header bytes",
            limit: widen(MAX_HEADER_BYTES),
        });
    }
    let length = u32::try_from(json.len()).map_err(|_| IsolatedError::LimitExceeded {
        what: "request header bytes",
        limit: widen(MAX_HEADER_BYTES),
    })?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(REQUEST_MAGIC.len() + 4 + json.len())
        .map_err(|_| IsolatedError::LimitExceeded {
            what: "request header bytes",
            limit: widen(MAX_HEADER_BYTES),
        })?;
    frame.extend_from_slice(&REQUEST_MAGIC);
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

/// Encode everything of a page request frame that precedes the body: magic, header length and
/// header. The caller writes the `body_len` body bytes after it without copying them.
///
/// The dedupe cache, when present, is exported as a hash-only snapshot (one short lock);
/// `language` selects the pass of the language exchange.
///
/// # Errors
/// [`IsolatedError::Invalid`] for options that cannot be transported,
/// [`IsolatedError::Dedupe`] when the cache cannot be exported,
/// [`IsolatedError::LimitExceeded`] when the header exceeds [`MAX_HEADER_BYTES`].
pub fn encode_request_header(
    body_len: usize,
    base: &Url,
    options: &ExtractOptions,
    engine: Engine,
    secrets: &IsolatedSecrets,
    language: &LanguageStage,
) -> Result<Vec<u8>, IsolatedError> {
    secrets.check_bounds()?;
    let dedupe = options
        .dedupe_cache
        .as_ref()
        .map(crate::DedupeHandle::export_snapshot)
        .transpose()
        .map_err(IsolatedError::Dedupe)?;
    encode_header(
        body_len,
        Task::Page {
            engine,
            base_url: base.clone(),
            options: Box::new(options_to_transport(options)?),
            secrets: Box::new(secrets.clone()),
            dedupe: dedupe.map(Box::new),
            language: Box::new(language.clone()),
        },
    )
}

/// Encode the request frame head of an HTML upload parse. Options that only affect other
/// formats (PDF pages and markers, OCR) do not change an HTML parse and are not sent.
///
/// # Errors
/// [`IsolatedError::LimitExceeded`] when the header exceeds [`MAX_HEADER_BYTES`].
pub fn encode_upload_request_header(
    body_len: usize,
    filename: Option<&str>,
    content_type: Option<&str>,
    options: &ParseOptions,
) -> Result<Vec<u8>, IsolatedError> {
    encode_header(
        body_len,
        Task::UploadHtml {
            filename: filename.map(str::to_owned),
            content_type: content_type.map(str::to_owned),
            options: UploadOptionsTransport::from_options(options),
        },
    )
}

/// Plain, serializable form of an HTML [`ParsedDocument`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UploadReply {
    format: String,
    title: Option<String>,
    markdown: String,
    html: String,
    raw_html: String,
    text: String,
    links: Vec<String>,
    images: Vec<String>,
    metadata: std::collections::BTreeMap<String, serde_json::Value>,
    warnings: Vec<String>,
}

impl UploadReply {
    fn from_document(document: ParsedDocument) -> Self {
        let ParsedDocument {
            format,
            title,
            markdown,
            html,
            raw_html,
            text,
            links,
            images,
            metadata,
            warnings,
            ..
        } = document;
        Self {
            format: format.name().to_owned(),
            title,
            markdown,
            html,
            raw_html,
            text,
            links,
            images,
            metadata,
            warnings,
        }
    }

    fn into_document(self) -> Result<ParsedDocument, IsolatedError> {
        if self.format != ParseFormat::Html.name() {
            return Err(IsolatedError::Protocol {
                reason: "upload reply is not an HTML document".to_owned(),
            });
        }
        Ok(ParsedDocument {
            format: ParseFormat::Html,
            content_type: ParseFormat::Html.content_type(),
            title: self.title,
            markdown: self.markdown,
            html: self.html,
            raw_html: self.raw_html,
            text: self.text,
            links: self.links,
            images: self.images,
            metadata: self.metadata,
            num_pages: None,
            total_pages: None,
            pages: Vec::new(),
            layout: Vec::new(),
            warnings: self.warnings,
        })
    }
}

/// A decoded, validated helper reply.
#[derive(Debug)]
#[non_exhaustive]
pub enum Reply {
    /// The finished page and the dedupe observations it staged in the helper.
    Page {
        /// The document; its runtime dedupe commit is empty until the parent rebinds it.
        document: Box<Document>,
        /// Hash-only observations to rebind to the original handle ([`rebind_dedupe`]).
        dedupe_commit: Option<DedupeCommitEnvelopeV1>,
    },
    /// The native pipeline asked for language detection: run the original detector
    /// ([`LanguageCallV1::run`]) and send a [`LanguageStage::Replay`] request.
    NeedLanguage(LanguageCallV1),
    /// The parsed HTML upload.
    Upload(Box<ParsedDocument>),
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", rename_all_fields = "camelCase")]
enum ResponseIn {
    Page {
        document: Box<Document>,
        #[serde(default)]
        dedupe_commit: Option<DedupeCommitEnvelopeV1>,
    },
    NeedLanguage(LanguageCallV1),
    Upload(Box<UploadReply>),
    Err(Failure),
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case", rename_all_fields = "camelCase")]
enum ResponseOut<'a> {
    Page {
        document: &'a Document,
        dedupe_commit: Option<&'a DedupeCommitEnvelopeV1>,
    },
    NeedLanguage(&'a LanguageCallV1),
    Upload(&'a UploadReply),
    Err(&'a Failure),
}

/// Parent bytes the decode of `stdout` into a reply may need, counted before any document is
/// constructed. The wire size is not a memory bound: a two-byte `{}` can become a struct with
/// many empty collections. The cost is `3 x wire bytes` (buffer, parsed payload, transient
/// strings) plus [`DECODE_BYTES_PER_JSON_VALUE`] for every JSON value start outside string
/// literals, found by a linear scan that allocates nothing.
#[must_use]
pub fn response_decode_cost(stdout: &[u8]) -> usize {
    let (mut values, mut in_string, mut escaped) = (0_usize, false, false);
    for byte in stdout {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                values = values.saturating_add(1);
            }
            b'{' | b'[' | b',' => values = values.saturating_add(1),
            _ => {}
        }
    }
    stdout
        .len()
        .saturating_mul(3)
        .saturating_add(values.saturating_mul(DECODE_BYTES_PER_JSON_VALUE))
}

/// Decode the helper's standard output.
///
/// Up to [`MAX_PREAMBLE_BYTES`] bytes before [`RESPONSE_MAGIC`] are skipped. The payload length
/// must match the bytes that follow and must not exceed `limits.max_response_bytes`. Admit
/// [`response_decode_cost`] before calling.
///
/// # Errors
/// [`IsolatedError::Protocol`] for a missing or inconsistent frame,
/// [`IsolatedError::Rejected`] for a typed refusal of the helper,
/// [`IsolatedError::Unsupported`] when the helper refused a non-HTML upload.
pub fn parse_response_stream(stdout: &[u8], limits: &HelperLimits) -> Result<Reply, IsolatedError> {
    let protocol = |reason: &str| IsolatedError::Protocol {
        reason: reason.to_owned(),
    };
    let window = &stdout[..stdout.len().min(MAX_PREAMBLE_BYTES + RESPONSE_MAGIC.len())];
    let start = window
        .windows(RESPONSE_MAGIC.len())
        .position(|candidate| candidate == RESPONSE_MAGIC)
        .ok_or_else(|| protocol("response frame is missing"))?;
    let rest = &stdout[start + RESPONSE_MAGIC.len()..];
    let (length, payload) = rest
        .split_first_chunk::<8>()
        .ok_or_else(|| protocol("response length is truncated"))?;
    let length = u64::from_le_bytes(*length);
    if length > limits.max_response_bytes {
        return Err(IsolatedError::LimitExceeded {
            what: "response bytes",
            limit: limits.max_response_bytes,
        });
    }
    if widen(payload.len()) != length {
        return Err(protocol("response length does not match the frame"));
    }
    match serde_json::from_slice::<ResponseIn>(payload) {
        Ok(ResponseIn::Page {
            document,
            dedupe_commit,
        }) => Ok(Reply::Page {
            document,
            dedupe_commit,
        }),
        Ok(ResponseIn::NeedLanguage(call)) => Ok(Reply::NeedLanguage(call)),
        Ok(ResponseIn::Upload(reply)) => Ok(Reply::Upload(Box::new(reply.into_document()?))),
        Ok(ResponseIn::Err(Failure::OutputTooLarge { limit, .. })) => Err(IsolatedError::LimitExceeded {
            what: "response bytes",
            limit,
        }),
        Ok(ResponseIn::Err(Failure::UploadFormat)) => Err(IsolatedError::Unsupported {
            capability: "non-HTML upload",
        }),
        Ok(ResponseIn::Err(failure)) => Err(IsolatedError::Rejected(failure)),
        Err(_) => Err(protocol("response payload is not a valid result")),
    }
}

impl Reply {
    /// The page of a [`Reply::Page`].
    ///
    /// # Errors
    /// [`IsolatedError::Protocol`] for any other reply.
    pub fn into_page(self) -> Result<(Box<Document>, Option<DedupeCommitEnvelopeV1>), IsolatedError> {
        match self {
            Self::Page {
                document,
                dedupe_commit,
            } => Ok((document, dedupe_commit)),
            _ => Err(IsolatedError::Protocol {
                reason: "unexpected reply kind".to_owned(),
            }),
        }
    }

    /// The document of a [`Reply::Upload`].
    ///
    /// # Errors
    /// [`IsolatedError::Protocol`] for any other reply.
    pub fn into_upload(self) -> Result<Box<ParsedDocument>, IsolatedError> {
        match self {
            Self::Upload(document) => Ok(document),
            _ => Err(IsolatedError::Protocol {
                reason: "unexpected reply kind".to_owned(),
            }),
        }
    }
}

/// Rebind the helper's dedupe observations to the ORIGINAL handle of `options`, checking every
/// identity field against the parent's own expectation (policy, page URL and the digest of the
/// exact bytes the extractor saw). Nothing is recorded: the cache changes only when the caller
/// commits the page. Without a dedupe handle or without a native content policy no commit can
/// exist and any envelope is a protocol violation.
///
/// # Errors
/// [`IsolatedError::Dedupe`] when the envelope does not match, [`IsolatedError::Protocol`]
/// for an envelope nobody asked for.
pub fn rebind_dedupe(
    document: &mut Document,
    envelope: Option<&DedupeCommitEnvelopeV1>,
    options: &ExtractOptions,
    base: &Url,
    body: &[u8],
    secrets: &IsolatedSecrets,
) -> Result<(), IsolatedError> {
    let (Some(handle), Some(policy)) = (&options.dedupe_cache, &options.content) else {
        document.dedupe_commit = None;
        return match envelope {
            None => Ok(()),
            Some(_) => Err(IsolatedError::Protocol {
                reason: "dedupe commit without a dedupe policy".to_owned(),
            }),
        };
    };
    let raw = Digest::of(RAW_HTML_DOMAIN, &prepared_body(body, options, secrets));
    handle
        .attach_commit(document, envelope, policy, base, raw)
        .map_err(IsolatedError::Dedupe)
}

// ---------------------------------------------------------------------------------------------
// Helper side
// ---------------------------------------------------------------------------------------------

/// Apply the helper's resource limits to the current process.
///
/// Address space and CPU come from `limits`; the helper also gets no core files, no file
/// writes, at most [`HELPER_MAX_OPEN_FILES`] descriptors and no new processes or threads. The
/// process-count limit is applied last so the earlier calls cannot be affected by it.
///
/// # Errors
/// The operating system's error, or `Unsupported` off Linux.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn apply_limits(limits: &HelperLimits) -> std::io::Result<()> {
    use rustix::process::{setrlimit, Resource, Rlimit};
    let set = |resource: Resource, current: u64, maximum: u64| {
        setrlimit(
            resource,
            Rlimit {
                current: Some(current),
                maximum: Some(maximum),
            },
        )
        .map_err(std::io::Error::from)
    };
    set(
        Resource::As,
        limits.address_space_bytes,
        limits.address_space_bytes,
    )?;
    set(
        Resource::Cpu,
        limits.cpu_seconds,
        limits.cpu_seconds.saturating_add(1),
    )?;
    set(Resource::Core, 0, 0)?;
    set(Resource::Fsize, 0, 0)?;
    set(Resource::Nofile, HELPER_MAX_OPEN_FILES, HELPER_MAX_OPEN_FILES)?;
    set(Resource::Nproc, 0, 0)
}

/// Apply the helper's resource limits to the current process.
///
/// # Errors
/// Always `Unsupported`: resource isolation is implemented for Linux only.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn apply_limits(_limits: &HelperLimits) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// The helper entry. Returns `None` unless the second argument is [`HELPER_SUBCOMMAND`], so the
/// binary can call it first thing in `main` for every invocation. On a match it applies the
/// resource limits, serves one request on standard input/output and returns the exit status
/// ([`EXIT_OK`], [`EXIT_USAGE`], [`EXIT_LIMITS`] or [`EXIT_IO`]).
///
/// Synchronous by design: nothing is allocated for the request before the limits are in place.
pub fn dispatch<I>(args: I) -> Option<u8>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    args.next()?;
    if args.next()? != HELPER_SUBCOMMAND {
        return None;
    }
    let Some(limits) = HelperLimits::from_args(args) else {
        return Some(EXIT_USAGE);
    };
    if limits.validate().is_err() {
        return Some(EXIT_USAGE);
    }
    if apply_limits(&limits).is_err() {
        return Some(EXIT_LIMITS);
    }
    // The address-space limit is this process's real memory bound; admission accounting against
    // a host-sized budget would only refuse inputs the limit still allows.
    crawlx_core::parser_memory::global().set_limit(usize::MAX);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    Some(run_session(&mut stdin.lock(), &mut stdout.lock(), &limits))
}

/// What a helper serves for one request.
enum Served {
    Page {
        document: Box<Document>,
        commit: Option<DedupeCommitEnvelopeV1>,
    },
    /// The captured language call; the hold keeps its reservation until the frame is written.
    NeedLanguage(LanguageCallV1, crate::isolated_language::LanguageHold),
    Upload(UploadReply),
}

fn bridge(error: impl std::fmt::Display) -> Failure {
    Failure::Bridge {
        message: error.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn serve_page(
    body: &[u8],
    base: &Url,
    transport: OptionsTransport,
    engine: Engine,
    secrets: &IsolatedSecrets,
    dedupe: Option<DedupeSnapshotTransportV1>,
    language: LanguageStage,
) -> Result<Served, Failure> {
    let mut options = options_from_transport(transport)?;
    if let Some(snapshot) = dedupe {
        options.dedupe_cache = Some(snapshot.restore().map_err(bridge)?);
    }
    let mut capture = None;
    let mut replay = None;
    match language {
        LanguageStage::Capture { bundle_digest } => {
            let capturing =
                LanguageCapture::new(bundle_digest, Arc::clone(crawlx_core::parser_memory::global()));
            options.language_detector = Some(capturing.handle());
            capture = Some(capturing);
        }
        LanguageStage::Replay(reply) => {
            let replaying = LanguageReplay::new(reply);
            options.language_detector = Some(replaying.handle());
            replay = Some(replaying);
        }
        _ => {}
    }
    let mut document =
        extract_local(body, base, &options, engine, secrets).map_err(|error| Failure::from(&error))?;
    if let Some(capturing) = capture {
        if let Some(captured) = capturing.take().map_err(bridge)? {
            let (call, hold) = captured.into_wire();
            return Ok(Served::NeedLanguage(call, hold));
        }
    }
    if let Some(replaying) = replay {
        replaying.finish().map_err(bridge)?;
    }
    let commit = DedupeCommitEnvelopeV1::take_from(&mut document).map_err(bridge)?;
    Ok(Served::Page {
        document: Box::new(document),
        commit,
    })
}

fn serve_upload(
    body: &[u8],
    filename: Option<&str>,
    content_type: Option<&str>,
    transport: UploadOptionsTransport,
) -> Result<Served, Failure> {
    let options = transport.into_options()?;
    match parse_upload_local(body, filename, content_type, &options) {
        Ok(document) => Ok(Served::Upload(UploadReply::from_document(document))),
        Err(IsolatedError::Unsupported { .. }) => Err(Failure::UploadFormat),
        Err(IsolatedError::Parse(error)) => Err(Failure::from(&*error)),
        Err(other) => Err(Failure::Upload {
            message: other.to_string(),
        }),
    }
}

/// Serve one request from `input` and write one response frame to `output`, without touching
/// process limits (the caller applied them, or a test does not want them).
pub fn run_session(input: &mut impl Read, output: &mut impl Write, limits: &HelperLimits) -> u8 {
    let served = read_request(input, limits).and_then(|(header, body)| match header.task {
        Task::Page {
            engine,
            base_url,
            options,
            secrets,
            dedupe,
            language,
        } => serve_page(
            &body,
            &base_url,
            *options,
            engine,
            &secrets,
            dedupe.map(|dedupe| *dedupe),
            *language,
        ),
        Task::UploadHtml {
            filename,
            content_type,
            options,
        } => serve_upload(&body, filename.as_deref(), content_type.as_deref(), options),
    });
    match write_response(output, limits, served.as_ref()) {
        Ok(()) => EXIT_OK,
        Err(_) => EXIT_IO,
    }
}

fn read_request(input: &mut impl Read, limits: &HelperLimits) -> Result<(Header, Vec<u8>), Failure> {
    let protocol = |message: &str| Failure::Protocol {
        message: message.to_owned(),
    };
    let resource = |what: &str| Failure::Resource {
        what: what.to_owned(),
    };
    let mut magic = [0_u8; 8];
    input
        .read_exact(&mut magic)
        .map_err(|_| protocol("request is truncated"))?;
    if magic != REQUEST_MAGIC {
        return Err(protocol("request magic mismatch"));
    }
    let mut length = [0_u8; 4];
    input
        .read_exact(&mut length)
        .map_err(|_| protocol("request header length is truncated"))?;
    let header_len = usize::try_from(u32::from_le_bytes(length)).map_err(|_| protocol("header too large"))?;
    if header_len > MAX_HEADER_BYTES || widen(header_len) > limits.max_request_bytes {
        return Err(protocol("request header exceeds its limit"));
    }
    let mut header_bytes = Vec::new();
    header_bytes
        .try_reserve_exact(header_len)
        .map_err(|_| resource("request header"))?;
    header_bytes.resize(header_len, 0);
    input
        .read_exact(&mut header_bytes)
        .map_err(|_| protocol("request header is truncated"))?;
    let header: Header =
        serde_json::from_slice(&header_bytes).map_err(|_| protocol("request header is not valid"))?;
    drop(header_bytes);
    if header.version != PROTOCOL_VERSION {
        return Err(protocol("unsupported protocol version"));
    }
    if let Task::Page { secrets, .. } = &header.task {
        secrets
            .check_bounds()
            .map_err(|_| protocol("secret bounds exceeded"))?;
    }
    let framed = widen(REQUEST_MAGIC.len() + 4 + header_len).saturating_add(header.body_len);
    if framed > limits.max_request_bytes {
        return Err(protocol("request exceeds the request limit"));
    }
    let body_len = usize::try_from(header.body_len).map_err(|_| resource("request body"))?;
    let mut body = Vec::new();
    body.try_reserve_exact(body_len)
        .map_err(|_| resource("request body"))?;
    body.resize(body_len, 0);
    input
        .read_exact(&mut body)
        .map_err(|_| protocol("request body is truncated"))?;
    Ok((header, body))
}

fn write_response(
    output: &mut impl Write,
    limits: &HelperLimits,
    result: Result<&Served, &Failure>,
) -> std::io::Result<()> {
    let serialize = |value: &ResponseOut<'_>| serde_json::to_vec(value).map_err(std::io::Error::from);
    let mut payload = match result {
        Ok(Served::Page { document, commit }) => serialize(&ResponseOut::Page {
            document,
            dedupe_commit: commit.as_ref(),
        })?,
        Ok(Served::NeedLanguage(call, _hold)) => serialize(&ResponseOut::NeedLanguage(call))?,
        Ok(Served::Upload(reply)) => serialize(&ResponseOut::Upload(reply))?,
        Err(failure) => serialize(&ResponseOut::Err(failure))?,
    };
    if widen(payload.len()) > limits.max_response_bytes {
        let failure = Failure::OutputTooLarge {
            limit: limits.max_response_bytes,
            actual: widen(payload.len()),
        };
        payload = serialize(&ResponseOut::Err(&failure))?;
    }
    output.write_all(&RESPONSE_MAGIC)?;
    output.write_all(&widen(payload.len()).to_le_bytes())?;
    output.write_all(&payload)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::Cursor;

    const PAGE: &[u8] = b"<html lang=\"en\"><head><title>Fixture page</title></head><body><nav><a href=\"/x\">x</a></nav>\
        <article><h1>Heading</h1><p>First paragraph of the fixture article with a token sk_live_fixture_secret_9 inside it.</p>\
        <p>Second paragraph with <a href=\"/more\">a link</a> and enough words to count.</p></article></body></html>";

    fn base() -> Url {
        Url::parse("https://fixture.test/page").unwrap()
    }

    fn limits() -> HelperLimits {
        HelperLimits::default()
    }

    fn serve(input: Vec<u8>, preamble: &[u8]) -> Vec<u8> {
        let mut output = preamble.to_vec();
        assert_eq!(
            run_session(&mut Cursor::new(input), &mut output, &limits()),
            EXIT_OK
        );
        output
    }

    /// The parent's side of the exchange: language capture pass, original detector, replay pass,
    /// then dedupe rebinding.
    fn through_session(
        body: &[u8],
        options: &ExtractOptions,
        engine: Engine,
        secrets: &IsolatedSecrets,
        preamble: &[u8],
    ) -> Result<Box<Document>, IsolatedError> {
        let mut stage = LanguageStage::first_pass(options);
        let mut passes = 0;
        loop {
            passes += 1;
            assert!(passes <= 2, "at most two passes");
            let mut input = encode_request_header(body.len(), &base(), options, engine, secrets, &stage)?;
            input.extend_from_slice(body);
            match parse_response_stream(&serve(input, preamble), &limits())? {
                Reply::Page {
                    mut document,
                    dedupe_commit,
                } => {
                    rebind_dedupe(
                        &mut document,
                        dedupe_commit.as_ref(),
                        options,
                        &base(),
                        body,
                        secrets,
                    )?;
                    return Ok(document);
                }
                Reply::NeedLanguage(call) => {
                    assert!(matches!(stage, LanguageStage::Capture { .. }));
                    let detector = options.language_detector.as_ref().unwrap();
                    stage = LanguageStage::Replay(call.run(detector.detector())?);
                }
                other => panic!("unexpected reply {other:?}"),
            }
        }
    }

    fn through_upload(
        body: &[u8],
        filename: Option<&str>,
        content_type: Option<&str>,
        options: &ParseOptions,
    ) -> Result<Box<ParsedDocument>, IsolatedError> {
        let mut input = encode_upload_request_header(body.len(), filename, content_type, options)?;
        input.extend_from_slice(body);
        parse_response_stream(&serve(input, b""), &limits())?.into_upload()
    }

    #[test]
    fn both_engines_round_trip_byte_identical_to_local_execution() {
        let secrets = IsolatedSecrets::default();
        for engine in [Engine::Pipeline, Engine::Extractor] {
            for options in [
                ExtractOptions::default(),
                ExtractOptions {
                    only_main_content: false,
                    include_tags: vec!["article".to_owned()],
                    discover_endpoints: true,
                    technologies: false,
                    headers: vec![("x-fixture".to_owned(), "1".to_owned())],
                    content_type: Some("text/html; charset=utf-8".to_owned()),
                    status: 203,
                    depth: 2,
                    max_nodes: 5000,
                    ..ExtractOptions::default()
                },
                ExtractOptions {
                    content: Some(ExtractionPolicyV1::default()),
                    image_references: true,
                    keep_data_images: true,
                    ..ExtractOptions::default()
                },
            ] {
                let local = extract_local(PAGE, &base(), &options, engine, &secrets).unwrap();
                let remote = through_session(PAGE, &options, engine, &secrets, b"").unwrap();
                assert_eq!(
                    serde_json::to_vec(&local).unwrap(),
                    serde_json::to_vec(&*remote).unwrap()
                );
                assert_eq!(local, *remote);
            }
        }
    }

    #[test]
    fn custom_fields_validation_redaction_decode_and_outputs_survive_the_transport() {
        let specs = vec![CustomFieldSpec {
            name: "token".to_owned(),
            regex: vec!["sk_live_([a-z_0-9]+)".to_owned()],
            part: crawlx_core::config::CustomFieldPart::Body,
            group: 1,
        }];
        let mut context = ValidationContextV1::default();
        context.target_status = Some(200);
        context.transport_succeeded = true;
        context.cached_body_available = true;
        let options = ExtractOptions {
            custom_fields: CustomField::compile_all(&specs).unwrap(),
            acquisition_validation: Some(context),
            content_redaction: Some(RedactOptions {
                mode: RedactMode::Aggressive,
                entities: [RedactEntity::Email, RedactEntity::Secret].into_iter().collect(),
                replace_style: ReplaceStyle::Mask,
            }),
            outputs: Some(ContentOutputOptions::default()),
            decode: Some(DecodeOptions::default()),
            markup: Some(MarkupRetention {
                comments: true,
                ..MarkupRetention::default()
            }),
            content: Some(ExtractionPolicyV1::default()),
            ..ExtractOptions::default()
        };
        let transport = options_to_transport(&options).unwrap();
        let rebuilt =
            options_from_transport(serde_json::from_slice(&serde_json::to_vec(&transport).unwrap()).unwrap())
                .unwrap();
        assert_eq!(rebuilt, options);
        let secrets = IsolatedSecrets::default();
        let local = extract_local(PAGE, &base(), &options, Engine::Pipeline, &secrets).unwrap();
        let remote = through_session(PAGE, &options, Engine::Pipeline, &secrets, b"").unwrap();
        assert_eq!(local, *remote);
        assert_eq!(remote.custom_fields["token"], vec!["fixture_secret_9".to_owned()]);
    }

    #[test]
    fn projection_secrets_cross_the_wire_and_match_local_projection() {
        let options = ExtractOptions {
            content: Some(ExtractionPolicyV1::default()),
            ..ExtractOptions::default()
        };
        let secrets = IsolatedSecrets::new(["sk_live_fixture_secret_9"], ["fixture article"]).unwrap();
        let local = extract_local(PAGE, &base(), &options, Engine::Pipeline, &secrets).unwrap();
        let remote = through_session(PAGE, &options, Engine::Pipeline, &secrets, b"").unwrap();
        assert_eq!(local, *remote);
        let text = serde_json::to_string(&*remote).unwrap();
        assert!(!text.contains("sk_live_fixture_secret_9"));
        assert!(!text.contains("fixture article"));
        assert!(text.contains("[REDACTED]"));
        assert!(!format!("{secrets:?}").contains("fixture"));
    }

    #[test]
    fn strict_projection_fails_closed_without_a_helper_difference() {
        let options = ExtractOptions {
            content: Some(ExtractionPolicyV1::default()),
            ..ExtractOptions::default()
        };
        let secrets = IsolatedSecrets::new([], ["zzzz-unused"]).unwrap();
        let local = extract_local(
            b"<p>\xff\xfe text</p>",
            &base(),
            &options,
            Engine::Extractor,
            &secrets,
        );
        let remote = through_session(
            b"<p>\xff\xfe text</p>",
            &options,
            Engine::Extractor,
            &secrets,
            b"",
        );
        assert_eq!(local.is_err(), remote.is_err());
    }

    fn dedupe_policy() -> ExtractionPolicyV1 {
        let mut policy = ExtractionPolicyV1::default();
        let mut dedupe = crawlx_core::extraction::DedupePolicyV1::default();
        dedupe.blocks = true;
        dedupe.content = true;
        policy.dedupe = Some(dedupe);
        policy
    }

    fn story(paragraphs: &[&str]) -> Vec<u8> {
        let body: String = paragraphs.iter().map(|p| format!("<p>{p}</p>")).collect();
        format!("<html><head><title>Ferry timetable</title></head><body><article><h1>Ferry timetable</h1>{body}</article></body></html>")
            .into_bytes()
    }

    const BOILERPLATE: &str = "Join the weekly newsletter for market updates delivered every morning.";
    const FIRST: &str = "The harbour authority announced new crossing times for the winter season on Monday.";
    const SECOND: &str =
        "Passengers on the northern route will see the earliest departure moved by twenty minutes.";

    #[test]
    fn dedupe_snapshot_crosses_and_the_commit_rebinds_without_touching_the_cache() {
        let cache = Arc::new(std::sync::Mutex::new(
            crawlx_core::extraction::DedupeCache::new(64).unwrap(),
        ));
        let handle = crate::DedupeHandle::new(
            crawlx_core::extraction::DedupeScopeV1::new("tenant", "run", "role").unwrap(),
            Arc::clone(&cache),
        );
        let options = ExtractOptions {
            content: Some(dedupe_policy()),
            dedupe_cache: Some(handle),
            only_main_content: false,
            ..ExtractOptions::default()
        };
        let secrets = IsolatedSecrets::default();
        let mut first = extract_local(
            &story(&[FIRST, BOILERPLATE]),
            &base(),
            &options,
            Engine::Pipeline,
            &secrets,
        )
        .unwrap();
        first.dedupe_commit.take().unwrap().record();
        let second = story(&[SECOND, BOILERPLATE]);
        let before = serde_json::to_vec(&cache.lock().unwrap().snapshot("tenant", "run")).unwrap();
        let local = extract_local(&second, &base(), &options, Engine::Pipeline, &secrets).unwrap();
        let remote = through_session(&second, &options, Engine::Pipeline, &secrets, b"").unwrap();
        assert!(
            local
                .article
                .as_ref()
                .unwrap()
                .dedupe
                .as_ref()
                .unwrap()
                .blocks_removed
                >= 1
        );
        assert_eq!(local, *remote);
        assert!(remote.dedupe_commit.is_some());
        assert_eq!(
            before,
            serde_json::to_vec(&cache.lock().unwrap().snapshot("tenant", "run")).unwrap(),
            "isolated parsing never writes the shared cache"
        );
        // Only the page commit changes the cache.
        let mut remote = remote;
        remote.dedupe_commit.take().unwrap().record();
        assert_ne!(
            before,
            serde_json::to_vec(&cache.lock().unwrap().snapshot("tenant", "run")).unwrap()
        );
    }

    #[test]
    fn a_dedupe_commit_that_does_not_match_the_parents_expectation_is_refused() {
        let cache = Arc::new(std::sync::Mutex::new(
            crawlx_core::extraction::DedupeCache::new(64).unwrap(),
        ));
        let options = ExtractOptions {
            content: Some(dedupe_policy()),
            dedupe_cache: Some(crate::DedupeHandle::new(
                crawlx_core::extraction::DedupeScopeV1::new("tenant", "run", "role").unwrap(),
                cache,
            )),
            ..ExtractOptions::default()
        };
        let secrets = IsolatedSecrets::default();
        let body = story(&[FIRST, SECOND]);
        let mut input = encode_request_header(
            body.len(),
            &base(),
            &options,
            Engine::Pipeline,
            &secrets,
            &LanguageStage::None,
        )
        .unwrap();
        input.extend_from_slice(&body);
        let (mut document, envelope) = parse_response_stream(&serve(input, b""), &limits())
            .unwrap()
            .into_page()
            .unwrap();
        let envelope = envelope.unwrap();
        let elsewhere = Url::parse("https://other.test/page").unwrap();
        let error = rebind_dedupe(
            &mut document,
            Some(&envelope),
            &options,
            &elsewhere,
            &body,
            &secrets,
        )
        .unwrap_err();
        assert!(matches!(error, IsolatedError::Dedupe(_)));
        assert!(document.dedupe_commit.is_none());
        let error = rebind_dedupe(
            &mut document,
            Some(&envelope),
            &options,
            &base(),
            b"another body",
            &secrets,
        )
        .unwrap_err();
        assert!(matches!(error, IsolatedError::Dedupe(_)));
        assert!(rebind_dedupe(&mut document, Some(&envelope), &options, &base(), &body, &secrets).is_ok());
        assert!(document.dedupe_commit.is_some());
    }

    struct FixtureDetector {
        digest: Digest,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl crawlx_core::article_language::ArticleLanguageDetector for FixtureDetector {
        fn detect(
            &self,
            _text: &str,
        ) -> Result<
            crawlx_core::article_language::LanguageDetectionV1,
            crawlx_core::article_language::LanguageDetectionErrorV1,
        > {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            use crawlx_core::article_language::{LanguageDetectionV1, LanguageScoreV1};
            LanguageDetectionV1::new(
                self.digest,
                vec![
                    LanguageScoreV1::new("en".to_owned(), 0.97)?,
                    LanguageScoreV1::new("de".to_owned(), 0.02)?,
                ],
                false,
            )
        }

        fn bundle_digest(&self) -> Digest {
            self.digest
        }
    }

    #[test]
    fn the_language_detector_runs_once_in_the_parent_and_replays_to_the_helper() {
        use crawlx_core::article_language::{ArticleLanguageHandle, LanguageModeV1};
        let digest = Digest::of("fixture.language.bundle", b"v1");
        let detector = Arc::new(FixtureDetector {
            digest,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut policy = ExtractionPolicyV1::default();
        policy.language_mode = LanguageModeV1::Detect;
        policy.language_bundle_digest = Some(digest);
        let options = ExtractOptions {
            content: Some(policy),
            language_detector: Some(ArticleLanguageHandle::new(detector.clone())),
            ..ExtractOptions::default()
        };
        let secrets = IsolatedSecrets::default();
        let local = extract_local(PAGE, &base(), &options, Engine::Pipeline, &secrets).unwrap();
        assert_eq!(detector.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let remote = through_session(PAGE, &options, Engine::Pipeline, &secrets, b"").unwrap();
        assert_eq!(
            detector.calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "one detection for the isolated run, in the parent"
        );
        assert_eq!(local, *remote);
        let metadata = &remote.article.as_ref().unwrap().metadata;
        assert_eq!(metadata.language_model_digest, Some(digest));
    }

    #[test]
    fn declared_language_needs_no_detector_exchange() {
        use crawlx_core::article_language::{ArticleLanguageHandle, LanguageModeV1};
        let digest = Digest::of("fixture.language.bundle", b"v1");
        let detector = Arc::new(FixtureDetector {
            digest,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut policy = ExtractionPolicyV1::default();
        policy.language_mode = LanguageModeV1::DeclaredThenDetect;
        policy.language_bundle_digest = Some(digest);
        let options = ExtractOptions {
            content: Some(policy),
            language_detector: Some(ArticleLanguageHandle::new(detector.clone())),
            ..ExtractOptions::default()
        };
        let secrets = IsolatedSecrets::default();
        let remote = through_session(PAGE, &options, Engine::Pipeline, &secrets, b"").unwrap();
        assert_eq!(detector.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            extract_local(PAGE, &base(), &options, Engine::Pipeline, &secrets).unwrap(),
            *remote
        );
    }

    #[test]
    fn html_uploads_match_the_api_parser_byte_for_byte_and_other_formats_are_refused() {
        let mut latin1 = b"<html><head><meta charset=\"windows-1252\"><title>Caf\xe9 menu</title></head><body><nav>menu</nav><main><p>Cr\xe8me br\xfbl\xe9e with <a href=\"/dessert\">dessert</a> <img src=\"/a.png\"></p></main></body></html>".to_vec();
        latin1.extend_from_slice(b"<!-- trailing -->");
        for options in [
            ParseOptions::default(),
            ParseOptions {
                only_main_content: false,
                include_tags: vec!["main".to_owned()],
                exclude_tags: vec!["nav".to_owned()],
                ..ParseOptions::default()
            },
        ] {
            for (body, name, kind) in [
                (PAGE, Some("page.html"), Some("text/html")),
                (latin1.as_slice(), Some("menu.htm"), None),
            ] {
                let expected = crate::parse::parse_document_with(body, name, kind, &options).unwrap();
                let local = parse_upload_local(body, name, kind, &options).unwrap();
                let remote = through_upload(body, name, kind, &options).unwrap();
                assert_eq!(local, expected);
                assert_eq!(*remote, expected);
                assert_eq!(remote.content_type, "text/html");
                assert_eq!(remote.format, ParseFormat::Html);
            }
        }
        let refused = through_upload(
            b"%PDF-1.4 not really",
            Some("a.pdf"),
            Some("application/pdf"),
            &ParseOptions::default(),
        );
        assert!(matches!(refused.unwrap_err(), IsolatedError::Unsupported { .. }));
        assert!(matches!(
            parse_upload_local(b"plain text", Some("a.txt"), None, &ParseOptions::default()).unwrap_err(),
            IsolatedError::Unsupported { .. }
        ));
    }

    #[test]
    fn upload_limits_and_selectors_fail_with_the_parsers_typed_errors() {
        let tight = ParseOptions {
            limits: ParseLimits {
                max_input_bytes: 16,
                ..ParseLimits::default()
            },
            ..ParseOptions::default()
        };
        let error = through_upload(PAGE, Some("page.html"), None, &tight).unwrap_err();
        assert!(matches!(error.into_parse_error(), ParseError::TooLarge { .. }));
        let bad = ParseOptions {
            include_tags: vec!["<<nope".to_owned()],
            ..ParseOptions::default()
        };
        let error = through_upload(PAGE, Some("page.html"), None, &bad).unwrap_err();
        assert!(matches!(
            error.into_parse_error(),
            ParseError::InvalidSelector { .. }
        ));
    }

    #[test]
    fn secrets_are_charged_before_they_are_copied_and_released_with_the_last_clone() {
        let budget = Arc::new(ByteBudget::new(1 << 20));
        let secrets = IsolatedSecrets::new_in(&budget, ["abcdefgh", ""], Some(["ijklmnop"])).unwrap();
        let reserved = budget.used();
        assert!(reserved >= 16);
        assert!(!format!("{secrets:?}").contains("abcdefgh"));
        let clone = secrets.clone();
        drop(secrets);
        assert_eq!(budget.used(), reserved, "clones share one reservation");
        drop(clone);
        assert_eq!(budget.used(), 0);
        let tiny = Arc::new(ByteBudget::new(8));
        let error = IsolatedSecrets::new_in(&tiny, ["abcdefgh"], None::<[&str; 0]>).unwrap_err();
        assert!(matches!(error, IsolatedError::Admission(_)));
        assert_eq!(tiny.used(), 0);
        let wire = serde_json::to_string(
            &IsolatedSecrets::new_in(&budget, ["abcdefgh"], None::<[&str; 0]>).unwrap(),
        )
        .unwrap();
        let restored: IsolatedSecrets = serde_json::from_str(&wire).unwrap();
        assert_eq!(restored.request().collect::<Vec<_>>(), ["abcdefgh"]);
        assert_eq!(restored.values.permit.as_ref().map(BytePermit::bytes), None);
    }

    #[test]
    fn typed_extract_failures_cross_the_wire() {
        let options = ExtractOptions {
            include_tags: vec!["<<not a selector".to_owned()],
            ..ExtractOptions::default()
        };
        let error = through_session(
            PAGE,
            &options,
            Engine::Extractor,
            &IsolatedSecrets::default(),
            b"",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            IsolatedError::Rejected(Failure::InvalidSelector { .. })
        ));
        assert!(matches!(
            error.into_extract_error(),
            ExtractError::InvalidSelector { .. }
        ));
        let options = ExtractOptions {
            max_nodes: 1,
            ..ExtractOptions::default()
        };
        let error = through_session(
            PAGE,
            &options,
            Engine::Extractor,
            &IsolatedSecrets::default(),
            b"",
        )
        .unwrap_err();
        assert!(matches!(
            error.into_extract_error(),
            ExtractError::TooLarge { what: "nodes", .. }
        ));
    }

    #[test]
    fn response_over_the_limit_is_a_typed_output_cap() {
        let small = HelperLimits {
            max_response_bytes: 512,
            ..limits()
        };
        let secrets = IsolatedSecrets::default();
        let mut input = encode_request_header(
            PAGE.len(),
            &base(),
            &ExtractOptions::default(),
            Engine::Pipeline,
            &secrets,
            &LanguageStage::None,
        )
        .unwrap();
        input.extend_from_slice(PAGE);
        let mut output = Vec::new();
        assert_eq!(run_session(&mut Cursor::new(input), &mut output, &small), EXIT_OK);
        let error = parse_response_stream(&output, &small).unwrap_err();
        assert!(error.is_resource_exhausted());
        assert!(matches!(
            error,
            IsolatedError::LimitExceeded {
                what: "response bytes",
                ..
            }
        ));
    }

    #[test]
    fn framing_tolerates_a_bounded_preamble_and_rejects_corruption() {
        let secrets = IsolatedSecrets::default();
        let options = ExtractOptions::default();
        assert!(through_session(PAGE, &options, Engine::Pipeline, &secrets, b"\nrunning 1 test\n").is_ok());
        let flood = vec![b'x'; MAX_PREAMBLE_BYTES + 64];
        assert!(matches!(
            through_session(PAGE, &options, Engine::Pipeline, &secrets, &flood).unwrap_err(),
            IsolatedError::Protocol { .. }
        ));
        assert!(matches!(
            parse_response_stream(b"", &limits()).unwrap_err(),
            IsolatedError::Protocol { .. }
        ));
        let mut truncated = RESPONSE_MAGIC.to_vec();
        truncated.extend_from_slice(&10_u64.to_le_bytes());
        truncated.extend_from_slice(b"{}");
        assert!(matches!(
            parse_response_stream(&truncated, &limits()).unwrap_err(),
            IsolatedError::Protocol { .. }
        ));
        let mut output = Vec::new();
        run_session(
            &mut Cursor::new(b"garbage garbage".to_vec()),
            &mut output,
            &limits(),
        );
        assert!(matches!(
            parse_response_stream(&output, &limits()).unwrap_err(),
            IsolatedError::Rejected(Failure::Protocol { .. })
        ));
    }

    #[test]
    fn decode_cost_counts_values_outside_strings_and_dwarfs_the_wire_size() {
        let hollow = [b"{\"ok\":[".as_slice(), &b"{},".repeat(1000), b"{}]}"].concat();
        let cost = response_decode_cost(&hollow);
        assert!(cost >= 1000 * DECODE_BYTES_PER_JSON_VALUE, "{cost}");
        assert!(cost > hollow.len() * 100);
        let quoted = br#"{"a":"[{,,,\"{[,"}"#;
        assert_eq!(
            response_decode_cost(quoted),
            quoted.len() * 3 + 3 * DECODE_BYTES_PER_JSON_VALUE
        );
        assert_eq!(response_decode_cost(b""), 0);
    }

    #[test]
    fn oversized_requests_and_bad_limits_are_refused() {
        let tiny = HelperLimits {
            max_request_bytes: 300,
            ..limits()
        };
        let secrets = IsolatedSecrets::default();
        let mut input = encode_request_header(
            PAGE.len(),
            &base(),
            &ExtractOptions::default(),
            Engine::Pipeline,
            &secrets,
            &LanguageStage::None,
        )
        .unwrap();
        input.extend_from_slice(PAGE);
        let mut output = Vec::new();
        run_session(&mut Cursor::new(input), &mut output, &tiny);
        assert!(matches!(
            parse_response_stream(&output, &limits()).unwrap_err(),
            IsolatedError::Rejected(Failure::Protocol { .. })
        ));
        assert!(HelperLimits {
            address_space_bytes: 1,
            ..limits()
        }
        .validate()
        .is_err());
        assert!(HelperLimits {
            cpu_seconds: 0,
            ..limits()
        }
        .validate()
        .is_err());
        assert!(limits().validate().is_ok());
    }

    #[test]
    fn secret_bounds_are_enforced() {
        let many = vec!["abcd"; MAX_SECRET_VALUES + 1];
        assert!(matches!(
            IsolatedSecrets::request_only(many).unwrap_err(),
            IsolatedError::Invalid { field: "secrets", .. }
        ));
        assert!(
            IsolatedSecrets::request_only(["", "abcd"])
                .unwrap()
                .values
                .request
                .len()
                == 1
        );
    }

    #[test]
    fn helper_arguments_round_trip_and_dispatch_ignores_other_commands() {
        let limits = HelperLimits {
            address_space_bytes: 100 * 1024 * 1024,
            cpu_seconds: 7,
            max_request_bytes: 4096,
            max_response_bytes: 8192,
        };
        let mut args = vec![OsString::from("crawlx")];
        args.extend(limits.helper_args());
        let mut it = args.into_iter();
        it.next();
        it.next();
        assert_eq!(HelperLimits::from_args(it), Some(limits));
        assert_eq!(
            dispatch([OsString::from("crawlx"), OsString::from("crawl")]),
            None
        );
        assert_eq!(dispatch([OsString::from("crawlx")]), None);
        assert_eq!(
            dispatch([
                OsString::from("crawlx"),
                OsString::from(HELPER_SUBCOMMAND),
                OsString::from("--bogus")
            ]),
            Some(EXIT_USAGE)
        );
    }

    #[test]
    fn resource_failures_convert_to_parse_memory() {
        for error in [
            IsolatedError::Timeout {
                timeout: Duration::from_secs(1),
            },
            IsolatedError::Signal { signal: 9 },
            IsolatedError::LimitExceeded {
                what: "response bytes",
                limit: 1,
            },
        ] {
            assert!(error.is_resource_exhausted());
            assert!(matches!(error.into_extract_error(), ExtractError::ParseMemory(_)));
        }
        assert!(!IsolatedError::Exit { code: 101 }.is_resource_exhausted());
        assert!(!IsolatedError::Cancelled.is_resource_exhausted());
    }
}
