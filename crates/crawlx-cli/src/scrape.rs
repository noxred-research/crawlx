//! Safe single-page scraping and a bounded, network-free stored-page REPL.
//!
//! Configuration precedence is defaults, tenant shaping defaults, config, request, flags.
//! Each invocation owns its normalized configuration; tenant defaults cannot supply authority.

use anyhow::{bail, Context as _};
use clap::{Args, ValueEnum};
use crawlx_core::selectors::{ItemLoaderV1, SelectorV1};
use crawlx_core::{CreateCrawl, SystemClock};
use crawlx_extract::item_loader::CompiledItemLoader;
use crawlx_extract::xpath::{CompiledSelector, SelectorDocument, XPathValue};
use crawlx_policy::{AdmissionPolicy, TenantLimits};
use crawlx_worker::stored_page::StoredPage;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _};
use tokio_util::sync::CancellationToken;
use url::Url;

const MAX_LINE: usize = 65_536;
const MAX_INPUT: usize = 1_048_576;
const MAX_COMMANDS: usize = 128;
const MAX_OUTPUT: usize = 1_048_576;
const MAX_PAGE: usize = 1_048_576;
const MAX_WORK: usize = 1_000_000;

/// Methods supported without journaled write intent.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum SafeMethod {
    /// Retrieve one page.
    #[default]
    #[value(name = "GET", alias = "get")]
    Get,
    /// Retrieve target response metadata without a body.
    #[value(name = "HEAD", alias = "head")]
    Head,
}
impl SafeMethod {
    fn http(self) -> http::Method {
        match self {
            Self::Get => http::Method::GET,
            Self::Head => http::Method::HEAD,
        }
    }
}

/// Explicit stdout representation.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PageOutput {
    /// Stored decoded HTML, or selector values as lines.
    Html,
    /// Article Markdown, or selector values as lines.
    #[default]
    Markdown,
    /// Extraction values as JSON; requires extraction for GET.
    Json,
}

/// Pure static extraction. Unknown types, executable callbacks and aliases are refused.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Extraction {
    /// Standards CSS, including text and attribute projections.
    Css {
        /// Static expression.
        expression: String,
    },
    /// Bounded XPath 1.0, with no external document functions.
    Xpath {
        /// Static expression.
        expression: String,
    },
    /// Linear-time regular expression over stored decoded HTML.
    Regex {
        /// Pattern, at most 512 bytes.
        pattern: String,
        /// Capture group; zero means whole match.
        #[serde(default)]
        group: usize,
    },
    /// Declarative item fields and offline schema.
    Item {
        /// Versioned native recipe.
        recipe: ItemLoaderV1,
    },
}
enum CompiledExtraction {
    Selector(CompiledSelector),
    Regex { regex: regex::Regex, group: usize },
    Item(CompiledItemLoader),
}

impl Extraction {
    fn compile(self) -> anyhow::Result<CompiledExtraction> {
        let compiled = match self {
            Self::Css { expression } => {
                CompiledExtraction::Selector(CompiledSelector::compile(&SelectorV1::Css { expression })?)
            }
            Self::Xpath { expression } => {
                CompiledExtraction::Selector(CompiledSelector::compile(&SelectorV1::Xpath { expression })?)
            }
            Self::Regex { pattern, group } => {
                let regex = crawlx_extract::regex_builtins::compile_regex(&pattern)?;
                if group >= regex.captures_len() {
                    bail!("regex capture group is out of range");
                }
                CompiledExtraction::Regex { regex, group }
            }
            Self::Item { recipe } => CompiledExtraction::Item(CompiledItemLoader::compile(&recipe)?),
        };
        if let CompiledExtraction::Selector(selector) = &compiled {
            selector.validate_namespaces(&BTreeMap::new())?;
        }
        Ok(compiled)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageConfig {
    method: Option<SafeMethod>,
    output: Option<PageOutput>,
    extraction: Option<Extraction>,
    crawl: Option<Value>,
}

/// Safe single-page arguments. Unsupported flags fail before any acquisition.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ScrapeArgs {
    /// The only URL acquired; config files cannot replace this explicit boundary.
    pub url: Url,
    /// GET or HEAD only. Body-bearing methods are unsupported.
    #[arg(long, value_enum)]
    pub method: Option<SafeMethod>,
    /// Output representation; JSON GET requires an extraction rule.
    #[arg(long, alias = "output", value_enum)]
    pub output_format: Option<PageOutput>,
    /// Select JSON output; conflicts with an explicit output representation.
    #[arg(long, conflicts_with = "output_format")]
    pub json: bool,
    /// Immutable JSON shaping defaults. May not set crawl authority or target settings.
    #[arg(long, value_name = "FILE")]
    pub tenant_config: Option<PathBuf>,
    /// JSON method/output/extraction and native crawl overrides.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Explicit JSON overrides applied after config and before flags.
    #[arg(long, value_name = "FILE")]
    pub request: Option<PathBuf>,
    /// CSS expression evaluated only against the stored page.
    #[arg(long, conflicts_with_all = ["xpath", "regex", "extraction"])]
    pub css: Option<String>,
    /// XPath expression evaluated only against the stored page.
    #[arg(long, conflicts_with_all = ["regex", "extraction"])]
    pub xpath: Option<String>,
    /// Linear-time regex evaluated only against the stored page.
    #[arg(long, conflicts_with = "extraction")]
    pub regex: Option<String>,
    /// JSON Extraction object. No code, imports or process commands are accepted.
    #[arg(long, value_name = "FILE")]
    pub extraction: Option<PathBuf>,
    /// Explicit authorization record; never read from tenant defaults.
    #[arg(long, value_name = "FILE")]
    pub authorization_record: Option<PathBuf>,
    /// Allow only private networks authorized by the explicit record.
    #[arg(long)]
    pub allow_private_networks: bool,
    /// Milestone gate directory.
    #[arg(long, value_name = "DIR")]
    pub gates_dir: Option<PathBuf>,
}

/// Stored-page shell. Commands never obtain another network capability.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ShellArgs {
    /// Single admitted acquisition and immutable request settings.
    #[command(flatten)]
    pub page: ScrapeArgs,
}

struct Effective {
    method: SafeMethod,
    output: PageOutput,
    extraction: Option<CompiledExtraction>,
    crawl: CreateCrawl,
}

fn read_config(path: &Path) -> anyhow::Result<PageConfig> {
    serde_json::from_slice(&crate::config_file::read_document(path)?)
        .context("invalid single-page JSON configuration")
}

fn effective(args: &ScrapeArgs) -> anyhow::Result<Effective> {
    let mut method = SafeMethod::default();
    let mut output = None;
    let mut extraction = None;
    let mut doc = serde_json::to_value(CreateCrawl::new(args.url.clone()))?;
    for (path, tenant) in [
        (args.tenant_config.as_deref(), true),
        (args.config.as_deref(), false),
        (args.request.as_deref(), false),
    ] {
        let Some(path) = path else { continue };
        let layer = read_config(path)?;
        if tenant && layer.crawl.is_some() {
            bail!("tenant defaults may only set method, output and extraction");
        }
        if let Some(value) = layer.method {
            method = value;
        }
        if let Some(value) = layer.output {
            output = Some(value);
        }
        if let Some(value) = layer.extraction {
            extraction = Some(value);
        }
        if let Some(value) = layer.crawl {
            let checked = crate::config_file::checked_body(value, path)?;
            if checked.get("seedUrl").is_some() {
                bail!("single-page configuration cannot override the explicit URL");
            }
            if checked.as_object().is_some_and(|object| {
                object.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "scope" | "fetch" | "safety" | "politeness" | "retention" | "limits"
                    )
                })
            }) {
                bail!("unsupported single-page crawl option");
            }
            crate::config_file::deep_merge(&mut doc, &checked);
        }
    }
    method = args.method.unwrap_or(method);
    let output = if args.json {
        PageOutput::Json
    } else {
        args.output_format
            .or(output)
            .unwrap_or(if method == SafeMethod::Head {
                PageOutput::Json
            } else {
                PageOutput::default()
            })
    };
    if let Some(expression) = &args.css {
        extraction = Some(Extraction::Css {
            expression: expression.clone(),
        });
    }
    if let Some(expression) = &args.xpath {
        extraction = Some(Extraction::Xpath {
            expression: expression.clone(),
        });
    }
    if let Some(pattern) = &args.regex {
        extraction = Some(Extraction::Regex {
            pattern: pattern.clone(),
            group: 0,
        });
    }
    if let Some(path) = &args.extraction {
        extraction = Some(
            serde_json::from_slice(&crate::config_file::read_document(path)?)
                .context("invalid extraction JSON")?,
        );
    }
    let extraction = extraction.map(Extraction::compile).transpose()?;
    if method == SafeMethod::Head && extraction.is_some() {
        bail!("HEAD has no stored body; extraction requires GET");
    }
    if method == SafeMethod::Head && output != PageOutput::Json {
        bail!("HEAD supports only JSON response metadata output");
    }
    let crawl = serde_json::from_value(doc).context("invalid single-page crawl overrides")?;
    Ok(Effective {
        method,
        output,
        extraction,
        crawl,
    })
}

async fn acquire(
    args: &ScrapeArgs,
    mut settings: Effective,
    getenv: &dyn Fn(&str) -> Option<String>,
    cancel: CancellationToken,
) -> anyhow::Result<(StoredPage, Effective)> {
    if cancel.is_cancelled() {
        bail!("stored-page command cancelled");
    }
    // Fix the single-page execution shape before admission, not after a wider request is admitted.
    settings.crawl.mode = crawlx_core::config::CrawlMode::Static;
    settings.crawl.dynamic.enabled = false;
    settings.crawl.limits.urls = 1;
    settings.crawl.scope.max_discovery_depth = 0;
    settings.crawl.scope.path_climb = false;
    settings.crawl.scope.known_files.clear();
    settings.crawl.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    settings.crawl.fetch.max_response_bytes = settings
        .crawl
        .fetch
        .max_response_bytes
        .min(u64::try_from(MAX_PAGE)?);
    if args.allow_private_networks {
        settings.crawl.safety.allow_private_networks = true;
    }
    let mut defaults = crate::crawl::CrawlArgs::default();
    defaults
        .authorization_record
        .clone_from(&args.authorization_record);
    defaults.gates_dir.clone_from(&args.gates_dir);
    let artifacts = tempfile::tempdir().context("creating ephemeral stored-page directory")?;
    let mut cfg = crate::crawl_run::base_config(&defaults, &settings.crawl, artifacts.path(), getenv)?;
    let record = args
        .authorization_record
        .as_deref()
        .map(crate::crawl_run::load_record)
        .transpose()?;
    if let Some(record) = &record {
        settings.crawl.safety.authorization_record_ref = Some(record.id);
    }
    let feed = crate::egress_feed::EgressFeed::start(getenv).await?;
    let admission = AdmissionPolicy::new(Arc::new(SystemClock))
        .with_gates(cfg.gates.status())
        .with_egress_lists(feed.lists());
    let admitted = admission
        .admit(&mut settings.crawl, &TenantLimits::default(), record.as_ref())
        .map_err(|_| anyhow::anyhow!("single-page request rejected by admission"))?;
    cfg.egress.extra_allow = admitted.egress.extra_allow;
    cfg.egress.extra_ports = admitted.egress.extra_ports;
    cfg.egress.lists = Some(feed.lists());
    cfg.egress.resolver_https = crate::resolver_https_config::from_env(getenv, feed.lists(), cancel.clone())?;
    let mut local = crawlx_worker::LocalRun::new(settings.crawl.clone(), cfg);
    if let Some(record) = record {
        local = local.with_authorization(record);
    }
    let page = crawlx_worker::stored_page::acquire(local, settings.method.http(), cancel).await?;
    Ok((page, settings))
}

/// Run one safe page acquisition and render its selected output.
///
/// # Errors
/// Invalid options, JSON without extraction, admission denial, cancellation or I/O failure.
pub async fn run(
    args: ScrapeArgs,
    out: &mut dyn Write,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<ExitCode> {
    let cancel = CancellationToken::new();
    let mut watcher = tokio::task::JoinSet::new();
    let signal = cancel.clone();
    watcher.spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.cancel();
        }
    });
    run_with_cancel(args, out, getenv, cancel).await
}

/// Run one acquisition with caller-owned cancellation, without installing signal handlers.
///
/// # Errors
/// Same failures as [`run`].
pub async fn run_with_cancel(
    args: ScrapeArgs,
    out: &mut dyn Write,
    getenv: &dyn Fn(&str) -> Option<String>,
    cancel: CancellationToken,
) -> anyhow::Result<ExitCode> {
    let settings = effective(&args)?;
    if settings.method == SafeMethod::Get
        && settings.output == PageOutput::Json
        && settings.extraction.is_none()
    {
        bail!("JSON output requires an explicit extraction rule");
    }
    let (page, settings) = acquire(&args, settings, getenv, cancel.clone()).await?;
    let bytes = if let Some(head) = &page.head {
        encode_bounded(head, MAX_OUTPUT)?
    } else if let Some(rule) = settings.extraction {
        let value = evaluate(Arc::new(page.html), Arc::new(page.url), rule, cancel.clone()).await?;
        render_value(&value, settings.output)?
    } else {
        let text = match settings.output {
            PageOutput::Html => page.html,
            PageOutput::Markdown => page.markdown,
            PageOutput::Json => bail!("JSON output requires an explicit extraction rule"),
        };
        if text.len() > MAX_OUTPUT {
            bail!("stored-page output limit exceeded");
        }
        text.into_bytes()
    };
    if cancel.is_cancelled() {
        bail!("stored-page command cancelled");
    }
    out.write_all(&bytes)?;
    writeln!(out)?;
    Ok(ExitCode::SUCCESS)
}

/// Start the bounded stdin REPL after one admitted GET acquisition.
///
/// # Errors
/// Invalid options, policy denial, cancellation, malformed commands or resource exhaustion.
pub async fn shell(
    args: ShellArgs,
    out: &mut dyn Write,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<ExitCode> {
    let cancel = CancellationToken::new();
    let mut watcher = tokio::task::JoinSet::new();
    let signal = cancel.clone();
    watcher.spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.cancel();
        }
    });
    shell_with_input(
        args,
        tokio::io::BufReader::new(tokio::io::stdin()),
        out,
        getenv,
        cancel,
    )
    .await
}

/// Start a stored-page REPL with bounded input and caller-owned cancellation.
///
/// Commands are `css EXPRESSION`, `xpath EXPRESSION`, `regex PATTERN`, `item JSON`, and
/// `quit`. Item JSON is an inline native ItemLoaderV1, never a filename or executable import.
/// Each successful command emits one JSON line. Errors stop without exposing command contents.
///
/// # Errors
/// Refuses non-GET acquisition, malformed/unsupported commands and all input/work/output overflow.
pub async fn shell_with_input<R: AsyncBufRead + Unpin>(
    args: ShellArgs,
    mut input: R,
    out: &mut dyn Write,
    getenv: &dyn Fn(&str) -> Option<String>,
    cancel: CancellationToken,
) -> anyhow::Result<ExitCode> {
    let settings = effective(&args.page)?;
    if settings.method != SafeMethod::Get {
        bail!("stored-page shell requires GET");
    }
    if settings.extraction.is_some() {
        bail!("shell extraction must be supplied as stored-page commands");
    }
    if args
        .page
        .output_format
        .is_some_and(|output| output != PageOutput::Json)
    {
        bail!("stored-page shell supports only JSON command output");
    }
    let (page, _) = acquire(&args.page, settings, getenv, cancel.clone()).await?;
    let mut input_bytes = 0usize;
    let mut output_bytes = 0usize;
    let mut work = 0usize;
    let html = Arc::new(page.html);
    let url = Arc::new(page.url);
    for _ in 0..MAX_COMMANDS {
        let line = read_line(&mut input, &cancel).await?;
        let Some(line) = line else {
            return Ok(ExitCode::SUCCESS);
        };
        input_bytes = input_bytes
            .checked_add(line.len())
            .context("shell input limit exceeded")?;
        if input_bytes > MAX_INPUT {
            bail!("shell input limit exceeded");
        }
        let command = line.trim();
        if command == "quit" {
            return Ok(ExitCode::SUCCESS);
        }
        let (kind, expression) = command
            .split_once(char::is_whitespace)
            .filter(|(_, expression)| !expression.trim().is_empty())
            .context("expected css, xpath, regex, item or quit")?;
        let expression = expression.trim();
        let rule = match kind {
            "css" => Extraction::Css {
                expression: expression.into(),
            },
            "xpath" => Extraction::Xpath {
                expression: expression.into(),
            },
            "regex" => Extraction::Regex {
                pattern: expression.into(),
                group: 0,
            },
            "item" => Extraction::Item {
                recipe: serde_json::from_str(expression).context("invalid inline item recipe")?,
            },
            _ => bail!("unsupported stored-page command; code and network commands are forbidden"),
        };
        let rule = rule.compile()?;
        // Charge reparsing and scanning against one session-wide deterministic ceiling.
        work = work
            .checked_add(html.len().max(1))
            .context("shell work limit exceeded")?;
        if work > MAX_WORK {
            bail!("shell work limit exceeded");
        }
        let value = evaluate(Arc::clone(&html), Arc::clone(&url), rule, cancel.clone()).await?;
        let remaining = MAX_OUTPUT.saturating_sub(output_bytes).saturating_sub(1);
        let bytes = encode_bounded(&value, remaining)?;
        output_bytes = output_bytes
            .checked_add(bytes.len())
            .and_then(|n| n.checked_add(1))
            .context("shell output limit exceeded")?;
        if cancel.is_cancelled() {
            bail!("stored-page shell cancelled");
        }
        out.write_all(&bytes)?;
        writeln!(out)?;
    }
    bail!("shell command limit exceeded")
}

async fn read_line<R: AsyncBufRead + Unpin>(
    input: &mut R,
    cancel: &CancellationToken,
) -> anyhow::Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        let available = tokio::select! {
            biased;
            () = cancel.cancelled() => bail!("stored-page shell cancelled"),
            value = input.fill_buf() => value?,
        };
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(
                    String::from_utf8(line).context("shell input must be UTF-8")?,
                ))
            };
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |i| i + 1);
        if count > MAX_LINE.saturating_sub(line.len()) {
            bail!("shell command exceeds input limit");
        }
        let done = available[count - 1] == b'\n';
        line.extend_from_slice(&available[..count]);
        input.consume(count);
        if done {
            return Ok(Some(
                String::from_utf8(line).context("shell input must be UTF-8")?,
            ));
        }
    }
}

async fn evaluate(
    html: Arc<String>,
    url: Arc<String>,
    rule: CompiledExtraction,
    cancel: CancellationToken,
) -> anyhow::Result<Value> {
    if html.len() > MAX_PAGE {
        bail!("stored page exceeds inspection limit");
    }
    let cancel = cancel.child_token();
    let _cancel_on_drop = cancel.clone().drop_guard();
    let task = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        if cancel.is_cancelled() {
            bail!("stored-page inspection cancelled");
        }
        if let CompiledExtraction::Regex { regex, group } = &rule {
            let mut values = Vec::new();
            let mut size = 0usize;
            for found in regex.captures_iter(&html) {
                if cancel.is_cancelled() {
                    bail!("stored-page inspection cancelled");
                }
                if let Some(value) = found.get(*group) {
                    size = size.saturating_add(value.len());
                    if values.len() >= 1000 || size > MAX_OUTPUT {
                        bail!("regex result limit exceeded");
                    }
                    values.push(Value::String(value.as_str().into()));
                }
            }
            return Ok(Value::Array(values));
        }
        let _charge = crawlx_extract::parse_budget::charge(html.len())?;
        // Admission bounds parser memory. The underlying HTML parser is not allocation-fallible.
        let dom = scraper::Html::parse_document(&html);
        let mut doc = SelectorDocument::with_operation_limit(&dom, MAX_WORK)?;
        let value = match rule {
            CompiledExtraction::Item(loader) => {
                let outcome = loader.load(&mut doc, &Url::parse(&url)?)?;
                if !outcome.valid {
                    bail!("item recipe produced an invalid item");
                }
                outcome.item
            }
            CompiledExtraction::Selector(selector) => match doc.evaluate(&selector, &BTreeMap::new())? {
                XPathValue::Nodes(nodes) => {
                    let mut values = Vec::with_capacity(nodes.len().min(1000));
                    if nodes.len() > 1000 {
                        bail!("selector result limit exceeded");
                    }
                    for node in nodes {
                        if cancel.is_cancelled() {
                            bail!("stored-page inspection cancelled");
                        }
                        values.push(Value::String(doc.string_value(node)?));
                    }
                    Value::Array(values)
                }
                XPathValue::String(value) => Value::String(value),
                XPathValue::Number(value) => json!(value),
                XPathValue::Boolean(value) => json!(value),
                _ => bail!("unsupported selector result"),
            },
            CompiledExtraction::Regex { .. } => bail!("invalid stored-page inspection dispatch"),
        };
        if cancel.is_cancelled() {
            bail!("stored-page inspection cancelled");
        }
        Ok(value)
    });
    // Join blocking work before releasing the stored bytes and parse reservation.
    task.await.context("stored-page inspection task failed")?
}

struct LimitedBytes {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for LimitedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("stored-page output limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn encode_bounded(value: &Value, limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut sink = LimitedBytes {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut sink, value).context("stored-page output limit exceeded")?;
    Ok(sink.bytes)
}
fn render_value(value: &Value, output: PageOutput) -> anyhow::Result<Vec<u8>> {
    if output == PageOutput::Json {
        return encode_bounded(value, MAX_OUTPUT);
    }
    let mut sink = LimitedBytes {
        bytes: Vec::new(),
        limit: MAX_OUTPUT,
    };
    if let Value::Array(values) = value {
        for (index, value) in values.iter().enumerate() {
            if index != 0 {
                sink.write_all(b"\n")?;
            }
            if let Some(text) = value.as_str() {
                sink.write_all(text.as_bytes())?;
            } else {
                serde_json::to_writer(&mut sink, value)?;
            }
        }
    } else if let Some(text) = value.as_str() {
        sink.write_all(text.as_bytes())?;
    } else {
        serde_json::to_writer(&mut sink, value)?;
    }
    Ok(sink.bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn output_limit_counts_encoded_json_not_unescaped_strings() {
        assert!(encode_bounded(&json!("\n\n\n\n"), 8).is_err());
        assert_eq!(encode_bounded(&json!("x"), 3).unwrap(), b"\"x\"");
    }

    #[tokio::test]
    async fn bounded_input_refuses_invalid_utf8_and_pending_cancel() {
        assert!(read_line(&mut &b"\xff\n"[..], &CancellationToken::new())
            .await
            .is_err());
        let cancel = CancellationToken::new();
        cancel.cancel();
        let (reader, _writer) = tokio::io::duplex(16);
        assert!(read_line(&mut tokio::io::BufReader::new(reader), &cancel)
            .await
            .is_err());
    }
}
