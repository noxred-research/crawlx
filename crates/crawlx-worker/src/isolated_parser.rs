//! Caller-fallible page parsing: admitted in-process when it provably fits, otherwise in a
//! resource-limited helper process.
//!
//! `scraper`/`html5ever` cannot refuse an allocation part way, so the parent never lets a page
//! that might not fit run in its own address space. [`IsolatedParser::extract_page`] decides per
//! call:
//!
//! * **In process** only when the input is at most
//!   [`IsolatedParserConfig::in_process_max_input`] and the parent can reserve what the parse
//!   needs: the measured `500 x input` DOM charge (probed against the shared budget, taken by the
//!   extractor itself), plus scratch for the decoded copy and the derived output. The document is
//!   returned with a reservation sized to its retained fields.
//! * **In a helper process** otherwise, or when the in-process attempt is refused by the shared
//!   parse-memory budget. The helper is the hidden `__isolated-parse` entry of the `crawlx`
//!   binary (see [`crawlx_extract::isolated::dispatch`]); it limits its own address space and CPU
//!   time before reading the request, runs with a cleared environment, no network and no file
//!   writes, and answers through a bounded frame. The parent streams the already admitted body
//!   to the helper without copying it and reads at most the configured response size.
//!
//! Every failure of the helper (signal, abnormal exit, timeout, oversized or malformed output,
//! cancellation) is a typed [`IsolatedError`]; the worker survives and every reservation is a
//! RAII permit that is released on every path. Cancellation kills the helper and reaps it before
//! returning; dropping the future kills it too.
//!
//! # Trusted handles
//!
//! Nothing is dropped and nothing is refused for isolation:
//!
//! * the **dedupe cache** crosses as a hash-only snapshot; the helper records nothing and returns
//!   its commit observations, which are rebound to the original handle after the parent checks
//!   every identity field (policy, page URL, digest of the exact bytes parsed). The shared cache
//!   changes only when the caller commits the page;
//! * the **language detector** never leaves the parent. The first helper run captures the text
//!   the native pipeline would classify, the parent runs the original detector once on the CPU
//!   pool, and a second run replays the digest-bound answer, so the document is the one the
//!   in-process route would build. At most two helper runs share one deadline;
//! * the **privacy projection secrets** travel in the request ([`IsolatedSecrets`], charged and
//!   redacted in `Debug`);
//! * **HTML uploads** use [`IsolatedParser::parse_upload_html`], which runs the API's
//!   `parse::parse_document_with` in both routes. Other upload formats keep their own bounds and
//!   are refused here with [`IsolatedError::Unsupported`].
//!
//! # Aggregate memory
//!
//! A helper's address-space limit bounds that helper only. Concurrent helpers are capped at
//! `min(max_concurrent_helpers, max(1, budget / address_space))` ([`IsolatedParser::helper_slots`])
//! and the worst-case aggregate address space is visible as
//! [`IsolatedParser::aggregate_helper_address_space`]. Operators must keep that sum, plus the
//! parent's own budget, under the container limit: isolation protects the worker from one page,
//! not the container from an oversized configuration.
//!
//! # Input ownership
//!
//! The input is a [`Budgeted<Bytes>`]. Its permit is the caller's reservation for the *derived*
//! document and is returned, grown to the document's retained size, with the result. It need not
//! cover the input: for shared acquisition bodies the [`Bytes`] owner already holds the source
//! charge (a zero-byte carrier permit is valid). The parser keeps the original [`Bytes`] owner
//! alive until the in-process blocking task or the helper exchange has finished.
//!
//! # Deployment
//!
//! The default helper is the current executable, which must be the `crawlx` binary.
//! `CRAWLX_PARSER_HELPER` (absolute path) selects another executable; there is no path guessing.
//! Embedders whose current executable is not the binary (for example test harnesses) inject a
//! [`HelperLauncher`].

use std::ffi::OsString;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::Bytes;
use crawlx_core::article_language::ArticleLanguageHandle;
use crawlx_core::parser_memory::{Budgeted, ByteBudget, BytePermit};
use crawlx_extract::isolated::{
    encode_request_header, encode_upload_request_header, extract_local, parse_response_stream,
    parse_upload_local, rebind_dedupe, response_decode_cost, LanguageStage, Reply, MAX_PREAMBLE_BYTES,
    RESPONSE_MAGIC,
};
pub use crawlx_extract::isolated::{Engine, HelperLimits, IsolatedError, IsolatedSecrets};
use crawlx_extract::parse::{ParseError, ParseOptions, ParsedDocument};
use crawlx_extract::{Document, ExtractError, ExtractOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::parser_memory::{run_admitted, AdmittedTaskError};
use crate::runtime::CpuPool;

/// Default largest input parsed in process: 1 MiB.
pub const DEFAULT_IN_PROCESS_MAX_INPUT: usize = 1024 * 1024;

/// Default wall-clock deadline of one helper run.
pub const DEFAULT_HELPER_TIMEOUT: Duration = Duration::from_secs(15);

/// Default number of helper processes alive at once.
pub const DEFAULT_MAX_CONCURRENT_HELPERS: NonZeroUsize = match NonZeroUsize::new(4) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};

/// Environment variable naming the helper executable (absolute path).
pub const HELPER_ENV: &str = "CRAWLX_PARSER_HELPER";

const MAX_CONCURRENT_HELPERS: usize = 256;
const MIN_TIMEOUT: Duration = Duration::from_millis(1);
const MAX_TIMEOUT: Duration = Duration::from_secs(3600);
/// Scratch for the decoded copy and derived output of an in-process parse, per input byte.
const SCRATCH_BYTES_PER_INPUT_BYTE: usize = 2;
const READ_CHUNK: usize = 32 * 1024;
const DOCUMENT_BASE_BYTES: usize = 16 * 1024;

/// Which executable runs the helper, with the arguments that precede the helper arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperLauncher {
    program: PathBuf,
    leading_args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
}

impl HelperLauncher {
    /// Launch `program`, which must be an absolute path to an executable that calls
    /// [`crawlx_extract::isolated::dispatch`] first thing in `main` (the `crawlx` binary).
    ///
    /// # Errors
    /// [`IsolatedError::Invalid`] for a relative path.
    pub fn new(program: impl Into<PathBuf>) -> Result<Self, IsolatedError> {
        let program = program.into();
        if !program.is_absolute() {
            return Err(IsolatedError::Invalid {
                field: "helper",
                reason: "the helper executable path must be absolute".to_owned(),
            });
        }
        Ok(Self {
            program,
            leading_args: Vec::new(),
            env: Vec::new(),
        })
    }

    /// The executable of the running process.
    ///
    /// # Errors
    /// [`IsolatedError::Io`] when the operating system cannot name it.
    pub fn current_exe() -> Result<Self, IsolatedError> {
        let program = std::env::current_exe().map_err(|source| IsolatedError::Io {
            stage: "locate helper executable",
            source,
        })?;
        Self::new(program)
    }

    /// Arguments placed before the helper arguments (for launchers that wrap the entry).
    #[must_use]
    pub fn with_leading_args(mut self, args: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        self.leading_args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Environment variables the helper receives. The environment is otherwise empty. This is
    /// an explicit embedder or test setting (for example sending an instrumented build's
    /// profile output to a device); production launchers pass nothing, so the helper inherits
    /// no ambient variables and no secrets.
    #[must_use]
    pub fn with_env(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<OsString>, impl Into<OsString>)>,
    ) -> Self {
        self.env = vars
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();
        self
    }

    /// The executable path.
    #[must_use]
    pub fn program(&self) -> &std::path::Path {
        &self.program
    }
}

/// Bounded configuration of the isolated parser.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IsolatedParserConfig {
    /// Inputs larger than this many bytes are never parsed in process.
    pub in_process_max_input: usize,
    /// Limits of one helper process and of the request/response frames.
    pub limits: HelperLimits,
    /// Wall-clock deadline of one helper run; the helper is killed when it passes.
    pub timeout: Duration,
    /// Helper processes alive at once; further calls wait (cancellably) for a slot.
    pub max_concurrent_helpers: NonZeroUsize,
    /// Helper executable; `None` selects the current executable when the parser is built.
    pub launcher: Option<HelperLauncher>,
}

impl Default for IsolatedParserConfig {
    fn default() -> Self {
        Self {
            in_process_max_input: DEFAULT_IN_PROCESS_MAX_INPUT,
            limits: HelperLimits::default(),
            timeout: DEFAULT_HELPER_TIMEOUT,
            max_concurrent_helpers: DEFAULT_MAX_CONCURRENT_HELPERS,
            launcher: None,
        }
    }
}

impl IsolatedParserConfig {
    /// Check every bound.
    ///
    /// # Errors
    /// [`IsolatedError::Invalid`] naming the offending field.
    pub fn validate(&self) -> Result<(), IsolatedError> {
        self.limits.validate()?;
        if !(MIN_TIMEOUT..=MAX_TIMEOUT).contains(&self.timeout) {
            return Err(IsolatedError::Invalid {
                field: "timeout",
                reason: "must be between 1 ms and 1 hour".to_owned(),
            });
        }
        if self.max_concurrent_helpers.get() > MAX_CONCURRENT_HELPERS {
            return Err(IsolatedError::Invalid {
                field: "maxConcurrentHelpers",
                reason: format!("must be at most {MAX_CONCURRENT_HELPERS}"),
            });
        }
        Ok(())
    }

    /// Read the optional overrides from the environment: `CRAWLX_PARSER_HELPER` (absolute
    /// path), `CRAWLX_PARSER_IN_PROCESS_MAX_BYTES`, `CRAWLX_PARSER_HELPER_ADDRESS_SPACE_BYTES`,
    /// `CRAWLX_PARSER_HELPER_CPU_SECONDS`, `CRAWLX_PARSER_HELPER_TIMEOUT_MS`,
    /// `CRAWLX_PARSER_HELPER_MAX_RESPONSE_BYTES` and `CRAWLX_PARSER_HELPER_MAX_CONCURRENT`.
    ///
    /// # Errors
    /// [`IsolatedError::Invalid`] for an unparsable or out-of-range value.
    pub fn from_env(getenv: &dyn Fn(&str) -> Option<String>) -> Result<Self, IsolatedError> {
        let number = |key: &'static str| -> Result<Option<u64>, IsolatedError> {
            getenv(key)
                .map(|value| {
                    value.trim().parse::<u64>().map_err(|_| IsolatedError::Invalid {
                        field: key,
                        reason: "not an unsigned integer".to_owned(),
                    })
                })
                .transpose()
        };
        let mut config = Self::default();
        if let Some(path) = getenv(HELPER_ENV) {
            config.launcher = Some(HelperLauncher::new(path)?);
        }
        if let Some(value) = number("CRAWLX_PARSER_IN_PROCESS_MAX_BYTES")? {
            config.in_process_max_input = usize::try_from(value).unwrap_or(usize::MAX);
        }
        if let Some(value) = number("CRAWLX_PARSER_HELPER_ADDRESS_SPACE_BYTES")? {
            config.limits.address_space_bytes = value;
        }
        if let Some(value) = number("CRAWLX_PARSER_HELPER_CPU_SECONDS")? {
            config.limits.cpu_seconds = value;
        }
        if let Some(value) = number("CRAWLX_PARSER_HELPER_MAX_RESPONSE_BYTES")? {
            config.limits.max_response_bytes = value;
        }
        if let Some(value) = number("CRAWLX_PARSER_HELPER_TIMEOUT_MS")? {
            config.timeout = Duration::from_millis(value);
        }
        if let Some(value) = number("CRAWLX_PARSER_HELPER_MAX_CONCURRENT")? {
            config.max_concurrent_helpers =
                usize::try_from(value)
                    .ok()
                    .and_then(NonZeroUsize::new)
                    .ok_or(IsolatedError::Invalid {
                        field: "CRAWLX_PARSER_HELPER_MAX_CONCURRENT",
                        reason: "must be a positive integer".to_owned(),
                    })?;
        }
        config.validate()?;
        Ok(config)
    }
}

/// Why a page was parsed in a helper process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsolationReason {
    /// The input is larger than [`IsolatedParserConfig::in_process_max_input`].
    InputOverCeiling,
    /// The parent could not reserve the parse's measured memory.
    MemoryPressure,
    /// The in-process attempt was refused by the shared parse-memory budget.
    ParseAdmissionRefused,
}

/// Where a page was parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseRoute {
    /// Admitted in the worker process.
    InProcess,
    /// Parsed by a resource-limited helper process.
    Isolated(IsolationReason),
}

/// One page extraction request. Options travel with the request, never ambient.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PageRequest {
    /// URL the document was fetched from.
    pub base: Url,
    /// Full extraction options.
    pub options: ExtractOptions,
    /// Entry point: [`Engine::Pipeline`] is what acquisition runs.
    pub engine: Engine,
    /// Literals of the privacy projection; see [`IsolatedSecrets`].
    pub secrets: IsolatedSecrets,
}

impl PageRequest {
    /// A request for the default pipeline engine without secrets.
    #[must_use]
    pub fn new(base: Url, options: ExtractOptions) -> Self {
        Self {
            base,
            options,
            engine: Engine::Pipeline,
            secrets: IsolatedSecrets::default(),
        }
    }
}

/// A parsed page and the reservation that covers it.
#[derive(Debug)]
#[non_exhaustive]
pub struct ParsedPage {
    /// Where the page was parsed.
    pub route: ParseRoute,
    /// The document; its permit is released after the document drops.
    pub document: Budgeted<Box<Document>>,
}

/// One HTML upload parse request.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UploadRequest {
    /// Uploaded file name, a format hint.
    pub filename: Option<String>,
    /// Declared content type, a format hint.
    pub content_type: Option<String>,
    /// Parser options. HTML honours the limits, `only_main_content` and the tag selectors; the
    /// PDF and OCR options only affect other formats.
    pub options: ParseOptions,
}

impl UploadRequest {
    /// A request with default options.
    #[must_use]
    pub fn new(filename: Option<String>, content_type: Option<String>) -> Self {
        Self {
            filename,
            content_type,
            options: ParseOptions::default(),
        }
    }
}

/// A parsed HTML upload and the reservation that covers it.
#[derive(Debug)]
#[non_exhaustive]
pub struct ParsedUpload {
    /// Where the upload was parsed.
    pub route: ParseRoute,
    /// The document; its permit is released after the document drops.
    pub document: Budgeted<Box<ParsedDocument>>,
}

/// Process-isolated page parser. Prefer [`shared`] in production: one instance bounds helper
/// concurrency for the whole process. Own instances are for tests and injected scoped services.
#[derive(Debug)]
pub struct IsolatedParser {
    config: IsolatedParserConfig,
    launcher: HelperLauncher,
    budget: Arc<ByteBudget>,
    slots: Arc<Semaphore>,
    slot_count: usize,
}

/// The process-wide parser, built once from the environment ([`IsolatedParserConfig::from_env`]).
///
/// # Errors
/// The (cached) configuration or launcher error.
pub fn shared() -> Result<&'static IsolatedParser, &'static IsolatedError> {
    static SHARED: LazyLock<Result<IsolatedParser, IsolatedError>> = LazyLock::new(|| {
        IsolatedParserConfig::from_env(&|key| std::env::var(key).ok()).and_then(IsolatedParser::new)
    });
    SHARED.as_ref()
}

enum Admission {
    InProcess(Option<BytePermit>),
    Isolate(IsolationReason),
}

enum Attempt<R, T> {
    Done(Result<T, IsolatedError>),
    Refused(R),
}

fn widen(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn task_error(error: AdmittedTaskError) -> IsolatedError {
    match error {
        AdmittedTaskError::Cancelled => IsolatedError::Cancelled,
        other => IsolatedError::Task(Box::new(other)),
    }
}

fn strings_bytes(values: &[String]) -> usize {
    values.iter().fold(0_usize, |total, value| {
        total.saturating_add(value.len()).saturating_add(24)
    })
}

/// Retained bytes of a document, an estimate that errs high: its large strings and lists plus
/// a fixed allowance for structured metadata.
fn estimate_document_bytes(document: &Document) -> usize {
    let strings = [
        document.markdown.len(),
        document.text.len(),
        document.html.len(),
        document.comments.len(),
    ]
    .into_iter()
    .fold(DOCUMENT_BASE_BYTES, usize::saturating_add);
    let links = document.links.iter().fold(0_usize, |total, link| {
        total
            .saturating_add(link.url.as_str().len())
            .saturating_add(link.text.len())
            .saturating_add(64)
    });
    let assets = document.assets.iter().fold(0_usize, |total, url| {
        total.saturating_add(url.as_str().len()).saturating_add(32)
    });
    let article = if document.article.is_some() {
        document.text.len().saturating_mul(2)
    } else {
        0
    };
    strings
        .saturating_add(links)
        .saturating_add(assets)
        .saturating_add(article)
}

fn estimate_upload_bytes(document: &ParsedDocument) -> usize {
    [
        document.markdown.len(),
        document.html.len(),
        document.raw_html.len(),
        document.text.len(),
        document.title.as_ref().map_or(0, String::len),
    ]
    .into_iter()
    .fold(DOCUMENT_BASE_BYTES, usize::saturating_add)
    .saturating_add(strings_bytes(&document.links))
    .saturating_add(strings_bytes(&document.images))
    .saturating_add(strings_bytes(&document.warnings))
    .saturating_add(document.metadata.len().saturating_mul(256))
}

/// A request shared with blocking verification tasks while the parent keeps its secrets alive.
type SharedRequest = Arc<PageRequest>;

impl IsolatedParser {
    /// Build a parser over the process-wide byte budget.
    ///
    /// # Errors
    /// Any [`IsolatedParserConfig::validate`] error, or the launcher lookup error.
    pub fn new(config: IsolatedParserConfig) -> Result<Self, IsolatedError> {
        let launcher = match &config.launcher {
            Some(launcher) => launcher.clone(),
            None => HelperLauncher::current_exe()?,
        };
        Self::with_launcher(config, launcher, Arc::clone(crawlx_core::parser_memory::global()))
    }

    fn with_launcher(
        config: IsolatedParserConfig,
        launcher: HelperLauncher,
        budget: Arc<ByteBudget>,
    ) -> Result<Self, IsolatedError> {
        config.validate()?;
        let slot_count = Self::slots_for(&config, &budget);
        Ok(Self {
            slots: Arc::new(Semaphore::new(slot_count)),
            slot_count,
            budget,
            config,
            launcher,
        })
    }

    fn slots_for(config: &IsolatedParserConfig, budget: &ByteBudget) -> usize {
        let per_helper = usize::try_from(config.limits.address_space_bytes).unwrap_or(usize::MAX);
        let by_budget = (budget.limit() / per_helper.max(1)).max(1);
        config.max_concurrent_helpers.get().min(by_budget)
    }

    /// Account the parent's transient bytes against `budget` instead of the process-wide one,
    /// and recompute the helper slot cap from it.
    #[must_use]
    pub fn with_parse_budget(mut self, budget: Arc<ByteBudget>) -> Self {
        self.slot_count = Self::slots_for(&self.config, &budget);
        self.slots = Arc::new(Semaphore::new(self.slot_count));
        self.budget = budget;
        self
    }

    /// The validated configuration.
    #[must_use]
    pub fn config(&self) -> &IsolatedParserConfig {
        &self.config
    }

    /// Helper processes that may run at once: the configured maximum, capped so that one helper
    /// address space per slot fits the byte budget this parser was built over.
    #[must_use]
    pub fn helper_slots(&self) -> usize {
        self.slot_count
    }

    /// Worst-case address space of all helpers together, in bytes. Keep it, plus the parent's
    /// own budget, under the container limit.
    #[must_use]
    pub fn aggregate_helper_address_space(&self) -> u64 {
        widen(self.slot_count).saturating_mul(self.config.limits.address_space_bytes)
    }

    /// Parse one page; see the module documentation for routing, ownership and trusted handles.
    ///
    /// `input` holds the body and the reservation for the derived document (it may be a
    /// zero-byte carrier when the [`Bytes`] owner holds the source charge).
    ///
    /// # Errors
    /// * [`IsolatedError::Cancelled`] when `cancel` fires (the helper, if any, is killed and
    ///   reaped before this returns);
    /// * [`IsolatedError::Extract`] for the extractor's own typed refusals;
    /// * [`IsolatedError::is_resource_exhausted`] failures for admission, size, deadline and
    ///   helper limit kills;
    /// * [`IsolatedError::Dedupe`] / [`IsolatedError::Language`] when a helper answer does not
    ///   match the parent's expectation;
    /// * the remaining variants for helper start-up, I/O and protocol failures.
    pub async fn extract_page(
        &self,
        cpu: &CpuPool,
        input: Budgeted<Bytes>,
        request: PageRequest,
        cancel: &CancellationToken,
    ) -> Result<ParsedPage, IsolatedError> {
        if cancel.is_cancelled() {
            return Err(IsolatedError::Cancelled);
        }
        let effective_max = if request.options.content.is_some() {
            request
                .options
                .max_input_bytes
                .min(crawlx_extract::document::DEFAULT_MAX_INPUT_BYTES)
        } else {
            request.options.max_input_bytes
        };
        match self.admit(input.value().len(), effective_max) {
            Admission::InProcess(scratch) => self.page_in_process(cpu, input, request, scratch, cancel).await,
            Admission::Isolate(reason) => {
                let (bytes, hold) = input.into_parts();
                self.page_isolated(cpu, bytes, hold, request, reason, cancel)
                    .await
            }
        }
    }

    /// Parse one HTML document upload with the API's parser: `parse::parse_document_with`
    /// in process, or the same function in a helper. Same routing, ownership and failure model
    /// as [`Self::extract_page`].
    ///
    /// # Errors
    /// [`IsolatedError::Unsupported`] for a non-HTML upload, [`IsolatedError::Parse`] for the
    /// parser's typed errors (convert with [`IsolatedError::into_parse_error`]), and the
    /// failures of [`Self::extract_page`].
    pub async fn parse_upload_html(
        &self,
        cpu: &CpuPool,
        input: Budgeted<Bytes>,
        request: UploadRequest,
        cancel: &CancellationToken,
    ) -> Result<ParsedUpload, IsolatedError> {
        if cancel.is_cancelled() {
            return Err(IsolatedError::Cancelled);
        }
        match self.admit(input.value().len(), request.options.limits.max_input_bytes) {
            Admission::InProcess(scratch) => {
                self.upload_in_process(cpu, input, request, scratch, cancel).await
            }
            Admission::Isolate(reason) => {
                let (bytes, hold) = input.into_parts();
                self.upload_isolated(cpu, bytes, hold, request, reason, cancel)
                    .await
            }
        }
    }

    fn admit(&self, len: usize, effective_max: usize) -> Admission {
        if len > effective_max {
            // Every entry point refuses this before allocating anything.
            return Admission::InProcess(None);
        }
        if len > self.config.in_process_max_input {
            return Admission::Isolate(IsolationReason::InputOverCeiling);
        }
        let probe = crawlx_extract::parse_budget::charge_bytes(len)
            .and_then(|bytes| self.budget.try_reserve(bytes).ok());
        let scratch = len
            .checked_mul(SCRATCH_BYTES_PER_INPUT_BYTE)
            .and_then(|bytes| self.budget.try_reserve(bytes).ok());
        // The probe only proves the measured DOM charge is available right now; the extractor
        // takes the real charge itself, so release the probe before it runs.
        match (probe, scratch) {
            (Some(probe), Some(scratch)) => {
                drop(probe);
                Admission::InProcess(Some(scratch))
            }
            _ => Admission::Isolate(IsolationReason::MemoryPressure),
        }
    }

    async fn page_in_process(
        &self,
        cpu: &CpuPool,
        input: Budgeted<Bytes>,
        request: PageRequest,
        scratch: Option<BytePermit>,
        cancel: &CancellationToken,
    ) -> Result<ParsedPage, IsolatedError> {
        let (bytes, hold) = input.into_parts();
        let spare = bytes.clone();
        let output = run_admitted(
            cpu,
            Budgeted::new((bytes, request, scratch), hold),
            cancel,
            move |(bytes, request, scratch), _permit, _cancel| {
                let result = extract_local(
                    &bytes,
                    &request.base,
                    &request.options,
                    request.engine,
                    &request.secrets,
                );
                drop(bytes);
                drop(scratch);
                match result {
                    Err(ExtractError::ParseMemory(_)) => Attempt::Refused(request),
                    other => Attempt::Done(other.map(Box::new).map_err(IsolatedError::from)),
                }
            },
        )
        .await
        .map_err(task_error)?;
        let (attempt, hold) = output.into_parts();
        match attempt {
            Attempt::Done(Ok(document)) => finish_page(document, hold, ParseRoute::InProcess),
            Attempt::Done(Err(error)) => Err(error),
            Attempt::Refused(request) => {
                tracing::debug!(
                    input_bytes = spare.len(),
                    "in-process parse refused by the shared budget; using the helper process"
                );
                self.page_isolated(
                    cpu,
                    spare,
                    hold,
                    request,
                    IsolationReason::ParseAdmissionRefused,
                    cancel,
                )
                .await
            }
        }
    }

    async fn upload_in_process(
        &self,
        cpu: &CpuPool,
        input: Budgeted<Bytes>,
        request: UploadRequest,
        scratch: Option<BytePermit>,
        cancel: &CancellationToken,
    ) -> Result<ParsedUpload, IsolatedError> {
        let (bytes, hold) = input.into_parts();
        let spare = bytes.clone();
        let output = run_admitted(
            cpu,
            Budgeted::new((bytes, request, scratch), hold),
            cancel,
            move |(bytes, request, scratch), _permit, _cancel| {
                let result = parse_upload_local(
                    &bytes,
                    request.filename.as_deref(),
                    request.content_type.as_deref(),
                    &request.options,
                );
                drop(bytes);
                drop(scratch);
                match result {
                    Err(IsolatedError::Parse(error)) if matches!(*error, ParseError::ParseMemory(_)) => {
                        Attempt::Refused(request)
                    }
                    other => Attempt::Done(other.map(Box::new)),
                }
            },
        )
        .await
        .map_err(task_error)?;
        let (attempt, hold) = output.into_parts();
        match attempt {
            Attempt::Done(Ok(document)) => finish_upload(document, hold, ParseRoute::InProcess),
            Attempt::Done(Err(error)) => Err(error),
            Attempt::Refused(request) => {
                tracing::debug!(
                    input_bytes = spare.len(),
                    "in-process upload parse refused by the shared budget; using the helper process"
                );
                self.upload_isolated(
                    cpu,
                    spare,
                    hold,
                    request,
                    IsolationReason::ParseAdmissionRefused,
                    cancel,
                )
                .await
            }
        }
    }

    async fn page_isolated(
        &self,
        cpu: &CpuPool,
        bytes: Bytes,
        hold: BytePermit,
        request: PageRequest,
        reason: IsolationReason,
        cancel: &CancellationToken,
    ) -> Result<ParsedPage, IsolatedError> {
        let deadline = tokio::time::Instant::now() + self.config.timeout;
        let request: SharedRequest = Arc::new(request);
        let mut stage = LanguageStage::first_pass(&request.options);
        let mut passes = 0_u8;
        loop {
            passes += 1;
            let header = encode_request_header(
                bytes.len(),
                &request.base,
                &request.options,
                request.engine,
                &request.secrets,
                &stage,
            )?;
            let reply = self
                .exchange_reply(
                    cpu,
                    header,
                    &bytes,
                    Some((Arc::clone(&request), bytes.clone())),
                    deadline,
                    cancel,
                )
                .await?;
            let (reply, decoded) = reply.into_parts();
            match reply? {
                Reply::Page { document, .. } => {
                    let page = finish_page(document, hold, ParseRoute::Isolated(reason));
                    drop(decoded);
                    return page;
                }
                Reply::NeedLanguage(call) => {
                    let handle = request.options.language_detector.clone();
                    let (Some(handle), 1) = (handle, passes) else {
                        return Err(IsolatedError::Protocol {
                            reason: "unexpected language request".to_owned(),
                        });
                    };
                    stage = self.run_detector(cpu, call, handle, decoded, cancel).await?;
                }
                _ => {
                    return Err(IsolatedError::Protocol {
                        reason: "unexpected reply kind".to_owned(),
                    })
                }
            }
        }
    }

    /// Run the original detector exactly once on the CPU pool. The decode reservation of the
    /// captured text stays alive for the whole call.
    async fn run_detector(
        &self,
        cpu: &CpuPool,
        call: crawlx_extract::isolated_language::LanguageCallV1,
        handle: ArticleLanguageHandle,
        decoded: BytePermit,
        cancel: &CancellationToken,
    ) -> Result<LanguageStage, IsolatedError> {
        let output = run_admitted(
            cpu,
            Budgeted::new((call, handle), decoded),
            cancel,
            |(call, handle), _permit, _cancel| call.run(handle.detector()),
        )
        .await
        .map_err(task_error)?;
        let (reply, permit) = output.into_parts();
        drop(permit);
        Ok(LanguageStage::Replay(reply?))
    }

    async fn upload_isolated(
        &self,
        cpu: &CpuPool,
        bytes: Bytes,
        hold: BytePermit,
        request: UploadRequest,
        reason: IsolationReason,
        cancel: &CancellationToken,
    ) -> Result<ParsedUpload, IsolatedError> {
        let deadline = tokio::time::Instant::now() + self.config.timeout;
        let header = encode_upload_request_header(
            bytes.len(),
            request.filename.as_deref(),
            request.content_type.as_deref(),
            &request.options,
        )?;
        let reply = self
            .exchange_reply(cpu, header, &bytes, None, deadline, cancel)
            .await?;
        let (reply, decoded) = reply.into_parts();
        let document = reply?.into_upload()?;
        let upload = finish_upload(document, hold, ParseRoute::Isolated(reason));
        drop(decoded);
        upload
    }

    /// One helper run: send the frame, read the bounded response, then decode it on the CPU pool
    /// under an admission that covers the buffer, the parsed payload and every JSON value.
    /// `verify` rebinds the dedupe commit of a page reply to the original handle there.
    async fn exchange_reply(
        &self,
        cpu: &CpuPool,
        header: Vec<u8>,
        body: &Bytes,
        verify: Option<(SharedRequest, Bytes)>,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<Budgeted<Result<Reply, IsolatedError>>, IsolatedError> {
        let limits = self.config.limits;
        if widen(header.len()).saturating_add(widen(body.len())) > limits.max_request_bytes {
            return Err(IsolatedError::LimitExceeded {
                what: "request bytes",
                limit: limits.max_request_bytes,
            });
        }
        let mut scratch = self.budget.try_reserve(header.len())?;
        let slot = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(IsolatedError::Cancelled),
            slot = Arc::clone(&self.slots).acquire_owned() => slot.map_err(|error| IsolatedError::Task(Box::new(error)))?,
        };
        let stdout = self
            .run_helper(&header, body, &mut scratch, deadline, cancel)
            .await?;
        drop(slot);
        drop(header);
        run_admitted(
            cpu,
            Budgeted::new(stdout, scratch),
            cancel,
            move |stdout, permit, _cancel| -> Result<Reply, IsolatedError> {
                // Admit the buffer, the parsed payload and every JSON value before a document
                // is constructed; a hollow-but-valid response is refused here.
                permit
                    .grow_to(response_decode_cost(&stdout))
                    .map_err(IsolatedError::from)?;
                let reply = parse_response_stream(&stdout, &limits)?;
                drop(stdout);
                match (reply, verify) {
                    (
                        Reply::Page {
                            mut document,
                            dedupe_commit,
                        },
                        Some((request, body)),
                    ) => {
                        // The raw-source digest is taken over the scrubbed body: admit its copy.
                        if request.options.content.is_some() && !request.secrets.is_empty() {
                            permit.grow_by(body.len()).map_err(IsolatedError::from)?;
                        }
                        rebind_dedupe(
                            &mut document,
                            dedupe_commit.as_ref(),
                            &request.options,
                            &request.base,
                            &body,
                            &request.secrets,
                        )?;
                        Ok(Reply::Page {
                            document,
                            dedupe_commit: None,
                        })
                    }
                    (reply, _) => Ok(reply),
                }
            },
        )
        .await
        .map_err(task_error)
    }

    async fn run_helper(
        &self,
        header: &[u8],
        body: &Bytes,
        scratch: &mut BytePermit,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, IsolatedError> {
        let mut command = tokio::process::Command::new(self.launcher.program());
        command
            .args(&self.launcher.leading_args)
            .args(self.config.limits.helper_args())
            .env_clear()
            .envs(self.launcher.env.iter().map(|(key, value)| (key, value)))
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(IsolatedError::Spawn)?;
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(IsolatedError::Cancelled),
            timed = tokio::time::timeout_at(
                deadline,
                exchange(&mut child, header, body, &self.config.limits, scratch),
            ) => match timed {
                Ok(result) => result,
                Err(_) => Err(IsolatedError::Timeout { timeout: self.config.timeout }),
            },
        };
        if outcome.is_err() {
            // Kill and reap before reporting, so no helper outlives the failed call.
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        outcome
    }
}

fn finish_page(
    document: Box<Document>,
    mut hold: BytePermit,
    route: ParseRoute,
) -> Result<ParsedPage, IsolatedError> {
    if let Err(error) = hold.grow_to(estimate_document_bytes(&document)) {
        // The reservation must outlive the document it failed to cover.
        drop(document);
        return Err(error.into());
    }
    Ok(ParsedPage {
        route,
        document: Budgeted::new(document, hold),
    })
}

fn finish_upload(
    document: Box<ParsedDocument>,
    mut hold: BytePermit,
    route: ParseRoute,
) -> Result<ParsedUpload, IsolatedError> {
    if let Err(error) = hold.grow_to(estimate_upload_bytes(&document)) {
        drop(document);
        return Err(error.into());
    }
    Ok(ParsedUpload {
        route,
        document: Budgeted::new(document, hold),
    })
}

#[cfg(unix)]
fn signal_of(status: &std::process::ExitStatus) -> Option<i32> {
    std::os::unix::process::ExitStatusExt::signal(status)
}

#[cfg(not(unix))]
fn signal_of(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

/// Feed the request, collect the bounded response and the exit status.
async fn exchange(
    child: &mut tokio::process::Child,
    header: &[u8],
    body: &Bytes,
    limits: &HelperLimits,
    scratch: &mut BytePermit,
) -> Result<Vec<u8>, IsolatedError> {
    let io = |stage: &'static str| move |source| IsolatedError::Io { stage, source };
    let mut stdin = child.stdin.take().ok_or(IsolatedError::Protocol {
        reason: "helper stdin unavailable".to_owned(),
    })?;
    let mut stdout = child.stdout.take().ok_or(IsolatedError::Protocol {
        reason: "helper stdout unavailable".to_owned(),
    })?;
    let write = async move {
        let sent = async {
            stdin.write_all(header).await?;
            stdin.write_all(body).await?;
            stdin.shutdown().await
        }
        .await;
        drop(stdin);
        match sent {
            // A helper that stops reading (it already answered or died) is judged by its
            // output and exit status, not by the broken pipe.
            Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => Err(io("write request")(error)),
            _ => Ok(()),
        }
    };
    let cap = limits
        .max_response_bytes
        .saturating_add(widen(RESPONSE_MAGIC.len() + 8 + MAX_PREAMBLE_BYTES));
    let read = async {
        let mut buffer: Vec<u8> = Vec::new();
        let mut chunk = vec![0_u8; READ_CHUNK];
        loop {
            let count = stdout.read(&mut chunk).await.map_err(io("read response"))?;
            if count == 0 {
                return Ok(buffer);
            }
            let needed = buffer.len().saturating_add(count);
            if widen(needed) > cap {
                return Err(IsolatedError::LimitExceeded {
                    what: "response bytes",
                    limit: limits.max_response_bytes,
                });
            }
            if needed > buffer.capacity() {
                let target = needed
                    .max(buffer.capacity().saturating_mul(2))
                    .min(usize::try_from(cap).unwrap_or(usize::MAX));
                scratch.grow_by(target - buffer.capacity())?;
                buffer.try_reserve_exact(target - buffer.len()).map_err(|_| {
                    IsolatedError::LimitExceeded {
                        what: "response buffer",
                        limit: limits.max_response_bytes,
                    }
                })?;
            }
            buffer.extend_from_slice(&chunk[..count]);
        }
    };
    let ((), buffer) = tokio::try_join!(write, read)?;
    let status = child.wait().await.map_err(io("wait for helper"))?;
    if let Some(signal) = signal_of(&status) {
        return Err(IsolatedError::Signal { signal });
    }
    if !status.success() {
        return Err(IsolatedError::Exit {
            code: status.code().unwrap_or(-1),
        });
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::extraction::ExtractionPolicyV1;
    use crawlx_extract::isolated::HELPER_SUBCOMMAND;

    const TRAMPOLINE: &str = "isolated_parser::tests::helper_entry";

    /// Entry the libtest binary serves when re-executed as the helper (`HelperLauncher` leading
    /// arguments select this test and pass the helper arguments after `--`). A normal test run
    /// finds no helper subcommand and returns at once.
    #[test]
    fn helper_entry() {
        let mut args = std::env::args()
            .skip_while(|arg| arg != HELPER_SUBCOMMAND)
            .peekable();
        if args.peek().is_none() {
            return;
        }
        let args = std::iter::once(OsString::from("crawlx")).chain(args.map(OsString::from));
        let code = crawlx_extract::isolated::dispatch(args).unwrap_or(crawlx_extract::isolated::EXIT_USAGE);
        std::process::exit(i32::from(code));
    }

    fn trampoline() -> HelperLauncher {
        HelperLauncher::current_exe()
            .unwrap()
            .with_leading_args(["--exact", TRAMPOLINE, "--nocapture", "--test-threads=1", "--"])
            // An instrumented test binary writes its profile at exit; the helper's file-size
            // limit stays zero, so the write goes to a device that limit does not govern.
            .with_env([("LLVM_PROFILE_FILE", "/dev/null")])
    }

    /// Loadable mappings are bounded by the file size; leave room for the parse itself.
    fn trampoline_limits() -> HelperLimits {
        let size = std::fs::metadata(std::env::current_exe().unwrap()).unwrap().len();
        let mut limits = HelperLimits::default();
        limits.address_space_bytes = size + 320 * 1024 * 1024;
        limits
    }

    type ErrorCheck = fn(&IsolatedError) -> bool;

    fn config(launcher: HelperLauncher) -> IsolatedParserConfig {
        IsolatedParserConfig {
            launcher: Some(launcher),
            limits: trampoline_limits(),
            timeout: Duration::from_secs(60),
            ..IsolatedParserConfig::default()
        }
    }

    fn shell(script: &str, dir: &std::path::Path) -> HelperLauncher {
        let path = dir.join("helper.sh");
        std::fs::write(&path, script).unwrap();
        HelperLauncher::new("/bin/sh").unwrap().with_leading_args([path])
    }

    fn budget() -> Arc<ByteBudget> {
        Arc::new(ByteBudget::new(1 << 30))
    }

    fn page(paragraphs: usize) -> Vec<u8> {
        let mut html = String::from(
            "<html lang=\"en\"><head><title>Fixture page</title></head><body><nav><a href=\"/x\">x</a></nav><article>",
        );
        for index in 0..paragraphs {
            html.push_str(&format!(
                "<p>Paragraph {index} of the fixture article mentions token sk_live_fixture_secret_9 and <a href=\"/more/{index}\">a link</a> with several words to count.</p>"
            ));
        }
        html.push_str("</article></body></html>");
        html.into_bytes()
    }

    fn base() -> Url {
        Url::parse("https://fixture.test/page").unwrap()
    }

    fn input(budget: &Arc<ByteBudget>, body: Vec<u8>) -> Budgeted<Bytes> {
        Budgeted::new(Bytes::from(body), budget.try_reserve(0).unwrap())
    }

    async fn run(
        parser: &IsolatedParser,
        budget: &Arc<ByteBudget>,
        body: Vec<u8>,
        request: PageRequest,
    ) -> Result<ParsedPage, IsolatedError> {
        parser
            .extract_page(
                &CpuPool::default(),
                input(budget, body),
                request,
                &CancellationToken::new(),
            )
            .await
    }

    #[tokio::test]
    async fn admitted_pages_parse_in_process_without_a_helper_and_release_everything() {
        let budget = budget();
        // The helper path does not exist: the in-process route must never touch it.
        let launcher = HelperLauncher::new("/nonexistent/crawlx-helper").unwrap();
        let parser = IsolatedParser::new(config(launcher))
            .unwrap()
            .with_parse_budget(Arc::clone(&budget));
        let body = page(8);
        for engine in [Engine::Pipeline, Engine::Extractor] {
            let mut request = PageRequest::new(base(), ExtractOptions::default());
            request.engine = engine;
            let expected =
                extract_local(&body, &request.base, &request.options, engine, &request.secrets).unwrap();
            let parsed = run(&parser, &budget, body.clone(), request).await.unwrap();
            assert_eq!(parsed.route, ParseRoute::InProcess);
            assert_eq!(**parsed.document.value(), expected);
            assert!(budget.used() > 0, "the document keeps a reservation");
            drop(parsed);
            assert_eq!(budget.used(), 0);
        }
    }

    #[tokio::test]
    async fn helper_output_is_identical_to_in_process_for_both_engines_with_full_options() {
        let budget = budget();
        let mut config = config(trampoline());
        config.in_process_max_input = 1;
        let parser = IsolatedParser::new(config)
            .unwrap()
            .with_parse_budget(Arc::clone(&budget));
        let body = page(12);
        let policy = ExtractionPolicyV1::default();
        let mut context = crawlx_core::acquisition::ValidationContextV1::default();
        context.target_status = Some(200);
        context.transport_succeeded = true;
        let variants = [
            ExtractOptions::default(),
            ExtractOptions {
                only_main_content: false,
                include_tags: vec!["article".to_owned()],
                discover_endpoints: true,
                headers: vec![("x-fixture".to_owned(), "1".to_owned())],
                content_type: Some("text/html".to_owned()),
                status: 203,
                depth: 3,
                max_nodes: 5000,
                ..ExtractOptions::default()
            },
            ExtractOptions {
                content: Some(policy),
                acquisition_validation: Some(context),
                image_references: true,
                ..ExtractOptions::default()
            },
        ];
        for engine in [Engine::Pipeline, Engine::Extractor] {
            for options in &variants {
                let mut request = PageRequest::new(base(), options.clone());
                request.engine = engine;
                request.secrets =
                    IsolatedSecrets::new_in(&budget, ["sk_live_fixture_secret_9"], Some(["Paragraph 3 of"]))
                        .unwrap();
                let expected =
                    extract_local(&body, &request.base, &request.options, engine, &request.secrets).unwrap();
                let parsed = run(&parser, &budget, body.clone(), request).await.unwrap();
                assert_eq!(
                    parsed.route,
                    ParseRoute::Isolated(IsolationReason::InputOverCeiling)
                );
                assert_eq!(
                    serde_json::to_vec(&expected).unwrap(),
                    serde_json::to_vec(&**parsed.document.value()).unwrap()
                );
                if options.content.is_some() {
                    let text = serde_json::to_string(&**parsed.document.value()).unwrap();
                    assert!(!text.contains("sk_live_fixture_secret_9") && !text.contains("Paragraph 3 of"));
                    assert!(text.contains("[REDACTED]"));
                }
                drop(parsed);
                assert_eq!(budget.used(), 0);
            }
        }
    }

    #[tokio::test]
    async fn shared_budget_pressure_falls_back_to_the_helper() {
        let body = page(200);
        // Below 500 x input, above what the helper exchange itself needs.
        let tight = Arc::new(ByteBudget::new(8 * 1024 * 1024));
        assert!(body.len() * 500 > tight.limit());
        let parser = IsolatedParser::new(config(trampoline()))
            .unwrap()
            .with_parse_budget(Arc::clone(&tight));
        let request = PageRequest::new(base(), ExtractOptions::default());
        let expected = extract_local(
            &body,
            &request.base,
            &request.options,
            request.engine,
            &request.secrets,
        )
        .unwrap();
        let parsed = run(&parser, &tight, body, request).await.unwrap();
        assert_eq!(
            parsed.route,
            ParseRoute::Isolated(IsolationReason::MemoryPressure)
        );
        assert_eq!(**parsed.document.value(), expected);
        drop(parsed);
        assert_eq!(tight.used(), 0);
    }

    struct FixtureDetector {
        digest: crawlx_core::hash::Digest,
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
            use crawlx_core::article_language::{LanguageDetectionV1, LanguageScoreV1};
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            LanguageDetectionV1::new(
                self.digest,
                vec![
                    LanguageScoreV1::new("en".to_owned(), 0.97)?,
                    LanguageScoreV1::new("de".to_owned(), 0.02)?,
                ],
                false,
            )
        }

        fn bundle_digest(&self) -> crawlx_core::hash::Digest {
            self.digest
        }
    }

    #[tokio::test]
    async fn language_detector_and_dedupe_cache_survive_isolation_with_in_process_semantics() {
        use crawlx_core::article_language::{ArticleLanguageHandle, LanguageModeV1};
        let digest = crawlx_core::hash::Digest::of("fixture.language.bundle", b"v1");
        let detector = Arc::new(FixtureDetector {
            digest,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let cache = Arc::new(std::sync::Mutex::new(
            crawlx_core::extraction::DedupeCache::new(64).unwrap(),
        ));
        let handle = crawlx_extract::DedupeHandle::new(
            crawlx_core::extraction::DedupeScopeV1::new("tenant", "run", "role").unwrap(),
            Arc::clone(&cache),
        );
        let mut policy = ExtractionPolicyV1::default();
        policy.language_mode = LanguageModeV1::Detect;
        policy.language_bundle_digest = Some(digest);
        let mut dedupe = crawlx_core::extraction::DedupePolicyV1::default();
        dedupe.blocks = true;
        dedupe.content = true;
        policy.dedupe = Some(dedupe);
        let options = ExtractOptions {
            content: Some(policy),
            only_main_content: false,
            language_detector: Some(ArticleLanguageHandle::new(detector.clone())),
            dedupe_cache: Some(handle),
            ..ExtractOptions::default()
        };
        let budget = budget();
        let body = page(6);
        let request = || {
            let mut request = PageRequest::new(base(), options.clone());
            request.secrets =
                IsolatedSecrets::new_in(&budget, ["sk_live_fixture_secret_9"], Some([])).unwrap();
            request
        };
        // Seed the cache so the second page has something to dedupe against.
        let mut seeded =
            extract_local(&body, &base(), &options, Engine::Pipeline, &request().secrets).unwrap();
        seeded.dedupe_commit.take().unwrap().record();
        let before = serde_json::to_vec(&cache.lock().unwrap().snapshot("tenant", "run")).unwrap();
        detector.calls.store(0, std::sync::atomic::Ordering::SeqCst);

        let mut config = config(trampoline());
        config.in_process_max_input = 1;
        let isolated = IsolatedParser::new(config)
            .unwrap()
            .with_parse_budget(Arc::clone(&budget));
        let admitted = IsolatedParser::new(self::config(
            HelperLauncher::new("/nonexistent/crawlx-helper").unwrap(),
        ))
        .unwrap()
        .with_parse_budget(Arc::clone(&budget));
        let near = run(&admitted, &budget, body.clone(), request()).await.unwrap();
        assert_eq!(near.route, ParseRoute::InProcess);
        let far = run(&isolated, &budget, body.clone(), request()).await.unwrap();
        assert_eq!(far.route, ParseRoute::Isolated(IsolationReason::InputOverCeiling));
        assert_eq!(
            detector.calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "one detection per call, always in the parent"
        );
        assert_eq!(**near.document.value(), **far.document.value());
        assert!(far.document.value().dedupe_commit.is_some());
        assert_eq!(
            before,
            serde_json::to_vec(&cache.lock().unwrap().snapshot("tenant", "run")).unwrap(),
            "parsing never writes the shared cache"
        );
        drop((near, far));
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn html_uploads_use_the_api_parser_in_both_routes_and_other_formats_are_refused() {
        let budget = budget();
        let body = page(5);
        let direct = crawlx_extract::parse::parse_document_with(
            &body,
            Some("page.html"),
            Some("text/html"),
            &ParseOptions::default(),
        )
        .unwrap();
        let request = || UploadRequest::new(Some("page.html".to_owned()), Some("text/html".to_owned()));
        let mut config = config(trampoline());
        config.in_process_max_input = 1;
        let isolated = IsolatedParser::new(config)
            .unwrap()
            .with_parse_budget(Arc::clone(&budget));
        let admitted = IsolatedParser::new(self::config(
            HelperLauncher::new("/nonexistent/crawlx-helper").unwrap(),
        ))
        .unwrap()
        .with_parse_budget(Arc::clone(&budget));
        let cpu = CpuPool::default();
        let cancel = CancellationToken::new();
        let near = admitted
            .parse_upload_html(&cpu, input(&budget, body.clone()), request(), &cancel)
            .await
            .unwrap();
        let far = isolated
            .parse_upload_html(&cpu, input(&budget, body.clone()), request(), &cancel)
            .await
            .unwrap();
        assert_eq!(near.route, ParseRoute::InProcess);
        assert_eq!(far.route, ParseRoute::Isolated(IsolationReason::InputOverCeiling));
        assert_eq!(**near.document.value(), direct);
        assert_eq!(**far.document.value(), direct);
        drop((near, far));
        let refused = isolated
            .parse_upload_html(
                &cpu,
                input(&budget, b"plain text upload".to_vec()),
                UploadRequest::new(Some("a.txt".to_owned()), None),
                &cancel,
            )
            .await
            .unwrap_err();
        assert!(matches!(refused, IsolatedError::Unsupported { .. }));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn helper_slots_are_capped_by_the_budget_and_the_aggregate_is_visible() {
        let launcher = HelperLauncher::new("/nonexistent/crawlx-helper").unwrap();
        let mut config = IsolatedParserConfig {
            launcher: Some(launcher),
            max_concurrent_helpers: NonZeroUsize::new(8).unwrap(),
            ..IsolatedParserConfig::default()
        };
        config.limits.address_space_bytes = 512 * 1024 * 1024;
        let parser = IsolatedParser::new(config.clone())
            .unwrap()
            .with_parse_budget(Arc::new(ByteBudget::new(1024 * 1024 * 1024)));
        assert_eq!(parser.helper_slots(), 2);
        assert_eq!(parser.aggregate_helper_address_space(), 1024 * 1024 * 1024);
        let tiny = IsolatedParser::new(config.clone())
            .unwrap()
            .with_parse_budget(Arc::new(ByteBudget::new(1)));
        assert_eq!(tiny.helper_slots(), 1, "never below one helper");
        let roomy = IsolatedParser::new(config)
            .unwrap()
            .with_parse_budget(Arc::new(ByteBudget::new(64 * 1024 * 1024 * 1024)));
        assert_eq!(roomy.helper_slots(), 8, "never above the configured maximum");
    }

    #[tokio::test]
    async fn address_space_exhaustion_kills_only_the_helper_and_the_worker_continues() {
        let budget = budget();
        let mut config = config(trampoline());
        config.in_process_max_input = 1;
        let parser = IsolatedParser::new(config)
            .unwrap()
            .with_parse_budget(Arc::clone(&budget));
        // 16 MiB of unclosed formatting elements: hundreds of MiB of tree for a bounded parse.
        let unit = b"<a><b><i><em><strong><font><u><s><big><small><p>t";
        let hostile: Vec<u8> = unit.iter().copied().cycle().take(15 * 1024 * 1024).collect();
        let options = ExtractOptions {
            max_nodes: 100_000_000,
            ..ExtractOptions::default()
        };
        let mut request = PageRequest::new(base(), options);
        request.engine = Engine::Extractor;
        let error = run(&parser, &budget, hostile, request).await.unwrap_err();
        assert!(error.is_resource_exhausted(), "{error:?}");
        let converted = error.into_extract_error();
        assert!(
            matches!(&converted, ExtractError::ParseMemory(exhausted) if exhausted.exceeds_budget()),
            "{converted:?}"
        );
        assert_eq!(budget.used(), 0);
        let body = page(3);
        let request = PageRequest::new(base(), ExtractOptions::default());
        let expected = extract_local(
            &body,
            &request.base,
            &request.options,
            request.engine,
            &request.secrets,
        )
        .unwrap();
        let parsed = run(&parser, &budget, body, request).await.unwrap();
        assert_eq!(**parsed.document.value(), expected);
    }

    #[tokio::test]
    async fn abnormal_exit_signal_garbage_and_overcap_output_are_typed_failures() {
        let dir = tempfile::tempdir().unwrap();
        let budget = budget();
        let cases: [(&str, ErrorCheck); 5] = [
            ("exit 7", |e| {
                matches!(e, IsolatedError::Exit { code: 7 }) && !e.is_resource_exhausted()
            }),
            ("kill -9 $$", |e| {
                matches!(e, IsolatedError::Signal { signal: 9 }) && e.is_resource_exhausted()
            }),
            ("printf garbage", |e| matches!(e, IsolatedError::Protocol { .. })),
            ("exec yes", |e| {
                matches!(
                    e,
                    IsolatedError::LimitExceeded {
                        what: "response bytes",
                        ..
                    }
                )
            }),
            (
                "printf '\\000CXISOR\\001'; printf '\\377\\377\\377\\377\\000\\000\\000\\000'",
                |e| {
                    matches!(
                        e,
                        IsolatedError::LimitExceeded {
                            what: "response bytes",
                            ..
                        }
                    )
                },
            ),
        ];
        for (script, check) in cases {
            let mut config = IsolatedParserConfig {
                launcher: Some(shell(script, dir.path())),
                in_process_max_input: 1,
                ..IsolatedParserConfig::default()
            };
            config.limits.max_response_bytes = 4096;
            let parser = IsolatedParser::new(config)
                .unwrap()
                .with_parse_budget(Arc::clone(&budget));
            let error = run(
                &parser,
                &budget,
                page(2),
                PageRequest::new(base(), ExtractOptions::default()),
            )
            .await
            .unwrap_err();
            assert!(check(&error), "{script}: {error:?}");
            assert_eq!(budget.used(), 0, "{script}");
        }
    }

    #[tokio::test]
    async fn hollow_but_valid_results_are_refused_before_decoding_and_release_permits() {
        let dir = tempfile::tempdir().unwrap();
        let payload = [b"{\"ok\":[".as_slice(), &b"{},".repeat(100_000), b"{}]}"].concat();
        let mut frame = RESPONSE_MAGIC.to_vec();
        frame.extend_from_slice(&u64::try_from(payload.len()).unwrap().to_le_bytes());
        frame.extend_from_slice(&payload);
        let frame_path = dir.path().join("frame.bin");
        std::fs::write(&frame_path, &frame).unwrap();
        let budget = Arc::new(ByteBudget::new(8 * 1024 * 1024));
        let mut config = IsolatedParserConfig {
            launcher: Some(shell(&format!("cat '{}'\n", frame_path.display()), dir.path())),
            in_process_max_input: 1,
            ..IsolatedParserConfig::default()
        };
        config.limits.max_response_bytes = 1024 * 1024;
        let parser = IsolatedParser::new(config)
            .unwrap()
            .with_parse_budget(Arc::clone(&budget));
        let error = run(
            &parser,
            &budget,
            page(2),
            PageRequest::new(base(), ExtractOptions::default()),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, IsolatedError::Admission(_)), "{error:?}");
        assert!(error.is_resource_exhausted());
        assert_eq!(budget.used(), 0);
    }

    #[cfg(target_os = "linux")]
    async fn spawn_sleeper(
        dir: &std::path::Path,
        timeout: Duration,
        budget: &Arc<ByteBudget>,
    ) -> (Arc<IsolatedParser>, std::path::PathBuf) {
        let pid_file = dir.join("pid");
        let script = format!("echo $$ > '{}'\nexec sleep 60\n", pid_file.display());
        let config = IsolatedParserConfig {
            launcher: Some(shell(&script, dir)),
            in_process_max_input: 1,
            timeout,
            ..IsolatedParserConfig::default()
        };
        let parser = IsolatedParser::new(config)
            .unwrap()
            .with_parse_budget(Arc::clone(budget));
        (Arc::new(parser), pid_file)
    }

    #[cfg(target_os = "linux")]
    async fn pid_of(pid_file: &std::path::Path) -> u32 {
        for _ in 0..500 {
            if let Ok(text) = std::fs::read_to_string(pid_file) {
                if let Ok(pid) = text.trim().parse() {
                    return pid;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("helper never started");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cancellation_kills_and_reaps_the_helper_and_releases_permits() {
        let dir = tempfile::tempdir().unwrap();
        let budget = budget();
        let (parser, pid_file) = spawn_sleeper(dir.path(), Duration::from_secs(60), &budget).await;
        let cancel = CancellationToken::new();
        let task = {
            let (parser, budget, cancel) = (Arc::clone(&parser), Arc::clone(&budget), cancel.clone());
            tokio::spawn(async move {
                parser
                    .extract_page(
                        &CpuPool::default(),
                        Budgeted::new(Bytes::from(page(2)), budget.try_reserve(4096).unwrap()),
                        PageRequest::new(base(), ExtractOptions::default()),
                        &cancel,
                    )
                    .await
            })
        };
        let pid = pid_of(&pid_file).await;
        assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
        cancel.cancel();
        let error = task.await.unwrap().unwrap_err();
        assert!(matches!(error, IsolatedError::Cancelled));
        assert!(!error.is_resource_exhausted());
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "the helper must be killed and reaped before the call returns"
        );
        assert_eq!(budget.used(), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dropping_the_future_kills_the_helper() {
        let dir = tempfile::tempdir().unwrap();
        let budget = budget();
        let (parser, pid_file) = spawn_sleeper(dir.path(), Duration::from_secs(60), &budget).await;
        let task = {
            let (parser, budget) = (Arc::clone(&parser), Arc::clone(&budget));
            tokio::spawn(async move {
                parser
                    .extract_page(
                        &CpuPool::default(),
                        Budgeted::new(Bytes::from(page(2)), budget.try_reserve(4096).unwrap()),
                        PageRequest::new(base(), ExtractOptions::default()),
                        &CancellationToken::new(),
                    )
                    .await
            })
        };
        let pid = pid_of(&pid_file).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        for _ in 0..500 {
            if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
                assert_eq!(budget.used(), 0);
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("helper outlived its dropped call");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_deadline_kills_a_stuck_helper_with_a_resource_error() {
        let dir = tempfile::tempdir().unwrap();
        let budget = budget();
        let (parser, pid_file) = spawn_sleeper(dir.path(), Duration::from_millis(300), &budget).await;
        let error = run(
            &parser,
            &budget,
            page(2),
            PageRequest::new(base(), ExtractOptions::default()),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, IsolatedError::Timeout { .. }));
        assert!(error.is_resource_exhausted());
        let pid = pid_of(&pid_file).await;
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn helper_slots_bound_concurrency_and_waiting_callers_cancel_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let budget = budget();
        let config = IsolatedParserConfig {
            launcher: Some(shell("exec sleep 60\n", dir.path())),
            in_process_max_input: 1,
            max_concurrent_helpers: NonZeroUsize::MIN,
            timeout: Duration::from_secs(30),
            ..IsolatedParserConfig::default()
        };
        let parser = Arc::new(
            IsolatedParser::new(config)
                .unwrap()
                .with_parse_budget(Arc::clone(&budget)),
        );
        let first = CancellationToken::new();
        let spawn_call = |cancel: CancellationToken| {
            let (parser, budget) = (Arc::clone(&parser), Arc::clone(&budget));
            tokio::spawn(async move {
                parser
                    .extract_page(
                        &CpuPool::default(),
                        Budgeted::new(Bytes::from(page(1)), budget.try_reserve(0).unwrap()),
                        PageRequest::new(base(), ExtractOptions::default()),
                        &cancel,
                    )
                    .await
            })
        };
        let running = spawn_call(first.clone());
        tokio::time::sleep(Duration::from_millis(300)).await;
        let second_cancel = CancellationToken::new();
        let waiting = spawn_call(second_cancel.clone());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !waiting.is_finished(),
            "the second call waits for the single slot"
        );
        second_cancel.cancel();
        assert!(matches!(
            waiting.await.unwrap().unwrap_err(),
            IsolatedError::Cancelled
        ));
        first.cancel();
        assert!(matches!(
            running.await.unwrap().unwrap_err(),
            IsolatedError::Cancelled
        ));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn configuration_is_bounded_and_environment_overrides_are_explicit() {
        assert!(IsolatedParserConfig::default().validate().is_ok());
        let config = IsolatedParserConfig {
            timeout: Duration::ZERO,
            ..IsolatedParserConfig::default()
        };
        assert!(config.validate().is_err());
        let mut config = IsolatedParserConfig::default();
        config.limits.cpu_seconds = 0;
        assert!(config.validate().is_err());
        let env = |key: &str| match key {
            HELPER_ENV => Some("/opt/crawlx/bin/crawlx".to_owned()),
            "CRAWLX_PARSER_IN_PROCESS_MAX_BYTES" => Some("2048".to_owned()),
            "CRAWLX_PARSER_HELPER_TIMEOUT_MS" => Some("2500".to_owned()),
            "CRAWLX_PARSER_HELPER_MAX_CONCURRENT" => Some("2".to_owned()),
            _ => None,
        };
        let config = IsolatedParserConfig::from_env(&env).unwrap();
        assert_eq!(config.in_process_max_input, 2048);
        assert_eq!(config.timeout, Duration::from_millis(2500));
        assert_eq!(config.max_concurrent_helpers.get(), 2);
        assert_eq!(
            config.launcher.unwrap().program(),
            std::path::Path::new("/opt/crawlx/bin/crawlx")
        );
        assert!(
            IsolatedParserConfig::from_env(&|key| (key == HELPER_ENV).then(|| "crawlx".to_owned())).is_err()
        );
        assert!(IsolatedParserConfig::from_env(&|key| {
            (key == "CRAWLX_PARSER_HELPER_CPU_SECONDS").then(|| "many".to_owned())
        })
        .is_err());
        assert!(HelperLauncher::new("relative/crawlx").is_err());
    }
}
