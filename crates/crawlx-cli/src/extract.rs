//! Offline file/stdin/source-tree HTML extraction. No clients or telemetry initialize.
//!
//! Stdout is the default sink. An explicit output file uses exclusive creation.
//! Image, read-more and schema references never authorize network acquisition.

#[path = "extract_batch.rs"]
mod batch;
#[path = "extract_tei.rs"]
mod tei;

use anyhow::{bail, Context};
use clap::{Args, ValueEnum};
use crawlx_core::extraction::{ExtractionPolicyV1, QualityStatusV1};
use crawlx_extract::{
    document::DEFAULT_MAX_INPUT_BYTES,
    serialize::{write_article, ArticleFormat, ArticleStream, ArticleWriteError},
    ExtractOptions, Extractor,
};
use crawlx_fetch::protocol::file::FileCorpus;
use crawlx_worker::runtime::CpuPool;
use std::{
    io::Write,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::ExitCode,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::sync::CancellationToken;
use url::Url;

/// Local HTML input and explicit native content policy.
#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("html_input").required(true).args(["input", "input_dir", "stdin_html", "tei_input"])))]
pub struct ExtractArgs {
    /// Read one regular HTML file; symlinks and special files are refused.
    #[arg(long, value_name = "FILE")]
    pub input: Option<PathBuf>,
    /// Read a bounded operator-owned source tree in lexical UTF-8 relative-path order.
    #[arg(long, value_name = "DIRECTORY")]
    pub input_dir: Option<PathBuf>,
    /// Read at most 16 MiB of HTML from standard input, not URLs.
    #[arg(long, alias = "stdin")]
    pub stdin_html: bool,
    /// Validate an existing UTF-8 TEI document/corpus against the full pinned RELAX NG schema.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["request", "validate_tei", "format", "base_url", "max_file_bytes"])]
    pub tei_input: Option<PathBuf>,
    /// Absolute HTTP(S) resolution base only. Never fetched. Required for HTML extraction.
    #[arg(long, value_name = "URL", required_unless_present = "tei_input")]
    pub base_url: Option<Url>,
    /// JSON ExtractionPolicyV1 file, at most 64 KiB. Omit for legacy selection.
    #[arg(long, value_name = "POLICY")]
    pub request: Option<PathBuf>,
    /// Shared article serializer. Batch formats have real collection/item boundaries.
    #[arg(long, value_enum, default_value = "json")]
    pub format: OfflineFormat,
    /// Create a new operator-selected file. Existing paths are never overwritten.
    /// Omit for volatile stdout; do not select a file when zero retention is required.
    #[arg(long, value_name = "NEW_FILE")]
    pub output: Option<PathBuf>,
    /// Validate each emitted TEI document with the full pinned local RELAX NG schema.
    #[arg(long)]
    pub validate_tei: bool,
    /// Maximum regular files attempted across the source tree.
    #[arg(long, requires = "input_dir", default_value_t = 1024, value_parser = clap::value_parser!(u16).range(1..=4096))]
    pub max_files: u16,
    /// Maximum total discovered entries, including directories and refused files.
    #[arg(long, requires = "input_dir", default_value_t = 4096, value_parser = clap::value_parser!(u16).range(1..=4096))]
    pub max_entries: u16,
    /// Maximum directory nesting below the canonical operator root.
    #[arg(long, requires = "input_dir", default_value_t = 32, value_parser = clap::value_parser!(u8).range(0..=64))]
    pub max_depth: u8,
    /// Maximum HTML bytes per file; can only narrow the parser's 16 MiB ceiling.
    #[arg(long, default_value_t = 16_777_216, value_parser = clap::value_parser!(u32).range(1..=16_777_216))]
    pub max_file_bytes: u32,
    /// Aggregate input-byte allowance, including failed-read reservations.
    #[arg(long, requires = "input_dir", default_value_t = 67_108_864, value_parser = clap::value_parser!(u32).range(1..=67_108_864))]
    pub max_total_bytes: u32,
}

/// Shared article output modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OfflineFormat {
    /// Native JSON document; batch mode uses a single array of source/document records.
    Json,
    /// One compact source/document record per line in batch mode.
    Jsonl,
    /// Main plain text; batch mode uses byte-length framing.
    Text,
    /// Native Markdown; batch mode uses byte-length framing.
    Markdown,
    /// Sanitized HTML; batch mode uses a single HTML document with section boundaries.
    Html,
    /// Spreadsheet-safe CSV with exactly one header per collection.
    Csv,
    /// Native article XML with one collection root in batch mode.
    Xml,
    /// TEI P5; --validate-tei explicitly enables local RELAX NG validation.
    Tei,
}
impl From<OfflineFormat> for ArticleFormat {
    fn from(value: OfflineFormat) -> Self {
        match value {
            OfflineFormat::Json => Self::Json,
            OfflineFormat::Jsonl => Self::Jsonl,
            OfflineFormat::Text => Self::Text,
            OfflineFormat::Markdown => Self::Markdown,
            OfflineFormat::Html => Self::Html,
            OfflineFormat::Csv => Self::Csv,
            OfflineFormat::Xml => Self::Xml,
            OfflineFormat::Tei => Self::Tei,
        }
    }
}

async fn bounded_read(reader: impl AsyncRead + Unpin, limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(limit.saturating_add(1))?)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > limit {
        bail!("offline input exceeds {limit} bytes");
    }
    Ok(bytes)
}

async fn regular_file(path: &Path, limit: usize, cancel: &CancellationToken) -> anyhow::Result<bytes::Bytes> {
    let name = path
        .file_name()
        .context("offline input must name a regular file")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical = tokio::fs::canonicalize(parent)
        .await
        .context("canonicalizing offline input directory")?;
    let corpus = FileCorpus::open(&canonical, 1)?;
    let mut url = FileCorpus::parse_url("file:///")?;
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("invalid offline file URL"))?
        .push(name.to_str().context("offline input filename must be UTF-8")?);
    let resource = corpus
        .acquire(
            &url,
            u32::try_from(limit)?,
            std::time::Duration::from_secs(30),
            cancel,
        )
        .await?;
    if !resource.children.is_empty() || url.path().ends_with('/') {
        bail!("offline input must be a regular file");
    }
    Ok(resource.body)
}

async fn extract(
    bytes: bytes::Bytes,
    base: std::sync::Arc<Url>,
    options: std::sync::Arc<ExtractOptions>,
    pool: &CpuPool,
    cancel: &CancellationToken,
) -> anyhow::Result<crawlx_extract::Document> {
    let task = pool.run(move || {
        let redactor = crawlx_telemetry::Redactor::new();
        let scrubbed = redactor.scrub_bytes(&bytes, std::iter::empty::<&str>());
        Extractor::extract_bytes_with_projection(scrubbed.as_ref(), &base, &options, &|text| match redactor
            .scrub_bytes(text.as_bytes(), std::iter::empty::<&str>())
        {
            std::borrow::Cow::Borrowed(_) => None,
            std::borrow::Cow::Owned(bytes) => Some(
                String::from_utf8(bytes)
                    .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()),
            ),
        })
    });
    tokio::select! {
        biased;
        () = cancel.cancelled() => bail!("offline extraction cancelled"),
        result = task => Ok(result.context("offline extraction task failed")??),
    }
}

fn quality_code(document: &crawlx_extract::Document) -> u8 {
    match document.article.as_ref().map(|a| a.quality.status) {
        Some(QualityStatusV1::Unavailable) => 3,
        Some(QualityStatusV1::Rejected | QualityStatusV1::Partial) => 2,
        _ => 0,
    }
}

async fn validate_document(
    document: &crawlx_extract::Document,
    validator: &tei::Validator,
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    let mut bytes = ValidationBytes(Vec::new());
    write_article(&mut bytes, document, ArticleFormat::Tei)?;
    validator.validate(&bytes.0, cancel).await
}

struct ValidationBytes(Vec<u8>);
impl Write for ValidationBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > 33_554_432 {
            return Err(std::io::Error::other("TEI validation output byte limit exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn batch_manifest(source: &str, reason: Option<&str>, ordinal: Option<u64>) -> anyhow::Result<()> {
    // Structured local stderr is the source-tree manifest. No raw parser error or document is logged.
    let mut err = std::io::stderr().lock();
    serde_json::to_writer(
        &mut err,
        &serde_json::json!({"version":1,"source":source,
        "status":if reason.is_some() { "refused" } else { "observed" }, "reason":reason,"ordinal":ordinal}),
    )?;
    err.write_all(b"\n")?;
    Ok(())
}

async fn load_article_language(
    policy: Option<&ExtractionPolicyV1>,
    pool: &CpuPool,
    cancel: &CancellationToken,
) -> anyhow::Result<Option<crawlx_core::article_language::ArticleLanguageHandle>> {
    use crawlx_core::article_language::{ArticleLanguageHandle, LanguageModeV1};
    let Some(policy) = policy.filter(|policy| policy.language_mode != LanguageModeV1::DeclaredOnly) else {
        return Ok(None);
    };
    if policy.language_bundle_digest != Some(crawlx_model::article_language::expected_bundle_digest()) {
        bail!("exact approved article language bundle unavailable");
    }
    let root = std::env::var_os("CRAWLX_ARTICLE_LANGUAGE_BUNDLE")
        .filter(|root| !root.is_empty())
        .context("operator article language bundle is not configured")?;
    let task = pool.run(move || crawlx_model::article_language::LocalArticleLanguage::open(Path::new(&root)));
    let detector = tokio::select! {
        biased;
        () = cancel.cancelled() => bail!("offline extraction cancelled"),
        result = task => result.context("offline language model task failed")??,
    };
    Ok(Some(ArticleLanguageHandle::new(std::sync::Arc::new(detector))))
}

async fn run_inner(
    args: &ExtractArgs,
    out: &mut dyn Write,
    cancel: &CancellationToken,
    batch: Option<batch::Batch>,
) -> anyhow::Result<ExitCode> {
    let validator = if args.validate_tei || args.tei_input.is_some() {
        Some(tei::Validator::prepare()?)
    } else {
        None
    };
    if let Some(path) = &args.tei_input {
        let bytes = regular_file(path, 33_554_432, cancel).await?;
        validator
            .as_ref()
            .context("TEI validator capability unavailable")?
            .validate(&bytes, cancel)
            .await?;
        let mut report = tei::provenance();
        report["valid"] = serde_json::Value::Bool(true);
        serde_json::to_writer(&mut *out, &report)?;
        out.write_all(b"\n")?;
        return Ok(ExitCode::SUCCESS);
    }
    let base = args
        .base_url
        .as_ref()
        .context("--base-url is required for HTML extraction")?;
    if !matches!(base.scheme(), "http" | "https") {
        bail!("--base-url must use http or https; it is never fetched");
    }
    if args.validate_tei && args.format != OfflineFormat::Tei {
        bail!("--validate-tei requires --format tei");
    }
    let policy = if let Some(path) = &args.request {
        let bytes = regular_file(path, 65_536, cancel).await?;
        let value: ExtractionPolicyV1 =
            serde_json::from_slice(&bytes).context("reading offline extraction policy")?;
        value.validate()?;
        Some(value)
    } else {
        None
    };
    let pool = CpuPool::with_permits(NonZeroUsize::MIN);
    let language_detector = match load_article_language(policy.as_ref(), &pool, cancel).await {
        Ok(detector) => detector,
        Err(_) if cancel.is_cancelled() => bail!("offline extraction cancelled"),
        Err(error) => {
            writeln!(
                std::io::stderr().lock(),
                "article language capability unavailable: {error:#}"
            )?;
            return Ok(ExitCode::from(3));
        }
    };
    let options = std::sync::Arc::new(ExtractOptions {
        content: policy,
        language_detector,
        ..ExtractOptions::default()
    });
    let base = std::sync::Arc::new(base.clone());
    if let Some(mut batch) = batch {
        let mut stream = ArticleStream::begin(out, args.format.into())?;
        let mut code = 0_u8;
        let mut ordinal = 0_u64;
        loop {
            let entry = match batch.next(cancel).await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(_) if cancel.is_cancelled() => bail!("offline extraction cancelled"),
                Err(_) => {
                    batch_manifest("", Some("batch_traversal_limit_or_io"), None)?;
                    code = code.max(2);
                    break;
                }
            };
            match entry {
                batch::Entry::Refused { source, reason } => {
                    batch_manifest(&source, Some(reason), None)?;
                    code = code.max(2);
                }
                batch::Entry::Document { source, bytes } => {
                    match extract(
                        bytes,
                        std::sync::Arc::clone(&base),
                        std::sync::Arc::clone(&options),
                        &pool,
                        cancel,
                    )
                    .await
                    {
                        Ok(document) => {
                            if let Some(validator) = &validator {
                                if validate_document(&document, validator, cancel).await.is_err() {
                                    if cancel.is_cancelled() {
                                        bail!("offline extraction cancelled");
                                    }
                                    batch_manifest(&source, Some("tei_validation_failed"), None)?;
                                    code = code.max(2);
                                    continue;
                                }
                            }
                            code = code.max(quality_code(&document));
                            match stream.push(&source, &document) {
                                Ok(()) => {}
                                Err(ArticleWriteError::InvalidXmlScalar) => {
                                    batch_manifest(&source, Some("invalid_xml_scalar"), None)?;
                                    code = code.max(2);
                                    continue;
                                }
                                Err(error) => return Err(error.into()),
                            }
                            batch_manifest(&source, None, Some(ordinal))?;
                            ordinal = ordinal.saturating_add(1);
                        }
                        Err(_) if cancel.is_cancelled() => bail!("offline extraction cancelled"),
                        Err(_) => {
                            batch_manifest(&source, Some("extraction_failed"), None)?;
                            code = code.max(2);
                        }
                    }
                }
            }
        }
        stream.finish()?;
        return Ok(ExitCode::from(code));
    }
    let bytes = if let Some(path) = &args.input {
        regular_file(path, usize::try_from(args.max_file_bytes)?, cancel).await?
    } else {
        tokio::select! {
            biased;
            () = cancel.cancelled() => bail!("offline extraction cancelled"),
            result = bounded_read(tokio::io::stdin(), usize::try_from(args.max_file_bytes)?.min(DEFAULT_MAX_INPUT_BYTES)) => bytes::Bytes::from(result?),
        }
    };
    let document = extract(bytes, base, options, &pool, cancel).await?;
    if let Some(validator) = &validator {
        validate_document(&document, validator, cancel).await?;
    }
    write_article(out, &document, args.format.into())?;
    Ok(ExitCode::from(quality_code(&document)))
}

/// Extract without initializing logging, OTLP, update checks or network services.
///
/// # Errors
/// Fails for policy, input, resource, schema capability or sink errors. Batch input
/// failures remain independent and emit structured stderr records. Explicit file
/// outputs are never overwritten; failed/cancelled invocations can leave partial output.
pub async fn run(args: ExtractArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let batch = args
        .input_dir
        .as_deref()
        .map(|root| batch::Batch::open(root, &args))
        .transpose()?;
    let cancel = CancellationToken::new();
    let mut signals = tokio::task::JoinSet::new();
    let signal_cancel = cancel.clone();
    signals.spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancel.cancel();
        }
    });
    let result = if let Some(path) = &args.output {
        if let Some(batch) = &batch {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            if tokio::fs::canonicalize(parent)
                .await?
                .starts_with(batch.canonical_root())
            {
                bail!("offline output must be outside the input source tree");
            }
        }
        let mut output_options = std::fs::OpenOptions::new();
        output_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            output_options.mode(0o600);
        }
        let mut file = output_options
            .open(path)
            .context("creating offline output without clobbering")?;
        let result = run_inner(&args, &mut file, &cancel, batch).await;
        file.flush()?;
        result
    } else {
        run_inner(&args, out, &cancel, batch).await
    };
    signals.abort_all();
    while signals.join_next().await.is_some() {}
    if cancel.is_cancelled() {
        return Ok(ExitCode::from(130));
    }
    result
}
