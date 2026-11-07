//! crawlx-telemetry: tracing subscriber, metrics registry and redaction layer
//! (see `docs/design/architecture.md`).
//!
//! * [`init`] installs the global subscriber: `EnvFilter` → [`RedactionLayer`]
//!   → a `fmt` layer driven by [`RedactingFormat`] (JSON or pretty). Every
//!   rendered field goes through the [`Redactor`]: deny-listed field names
//!   (`password`, `authorization`, `cookie`, `set-cookie`, `token`, `secret`,
//!   `credential`, …) and secret-shaped values (JWT, `Bearer …`, 32+ hex, `sk-…`,
//!   registered secrets) become `[REDACTED]`.
//! * [`build_subscriber`] builds the same stack over any `MakeWriter`; tests
//!   use it to capture output.
//! * [`metrics`] is the pure-Rust registry behind [`Metrics::global`], and
//!   [`spans`] holds the span-name hierarchy.
//! * [`trace_id`] gives every span tree a [`TraceId`](crawlx_core::ids::TraceId) that the
//!   storage journal writers copy onto `crawl_runs` and `actions` (the span-to-row join).
//! * OTLP export lives in one module, [`otlp`], behind the `otlp` cargo
//!   feature; with the feature off it is a no-op.

pub mod format;
pub mod metrics;
pub mod otlp;
pub mod redact;
pub mod spans;
pub mod trace_id;

pub use format::{LogFormat, RedactingFormat};
pub use metrics::{Counter, Gauge, Histogram, Metrics};
pub use otlp::OtlpConfig;
pub use redact::{register_secret, RedactionLayer, Redactor, REDACTED};
pub use trace_id::{current_trace_id, TraceIdLayer};

use tracing::Subscriber;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::EnvFilter;

/// Errors from telemetry initialization.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// The `EnvFilter` directive string did not parse.
    #[error("invalid log filter directive: {0}")]
    InvalidFilter(String),
    /// `tracing` allows one global subscriber per process and one is already set.
    #[error("a global tracing subscriber is already installed")]
    AlreadyInitialized,
    /// The configured OTLP endpoint is not an `http://` or `https://` URL.
    #[error("invalid OTLP endpoint {0:?}: expected an http:// or https:// URL")]
    InvalidOtlpEndpoint(String),
    /// The `otlp` feature is on but an exporter could not be built.
    #[error("OTLP exporter could not be built")]
    OtlpExporter(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Where log lines are written.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum LogOutput {
    /// Standard error (default); keeps stdout free for program output.
    #[default]
    Stderr,
    /// Standard output.
    Stdout,
}

/// Telemetry configuration.
#[derive(Clone, Debug)]
pub struct TelemetryConfig {
    /// `json` (default) or `pretty`.
    pub format: LogFormat,
    /// `EnvFilter` directives (e.g. `info,crawlx_worker=debug`). `None` reads
    /// `RUST_LOG` and falls back to `info`.
    pub filter: Option<String>,
    /// Destination stream of log lines.
    pub output: LogOutput,
    /// Extra field-name fragments to redact on top of the built-in deny-list.
    pub extra_redacted_fields: Vec<String>,
    /// OTLP settings; ignored (no-op) unless the `otlp` feature is enabled.
    pub otlp: Option<OtlpConfig>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Json,
            filter: None,
            output: LogOutput::Stderr,
            extra_redacted_fields: Vec::new(),
            otlp: None,
        }
    }
}

impl TelemetryConfig {
    fn env_filter(&self) -> Result<EnvFilter, TelemetryError> {
        match &self.filter {
            Some(directives) => {
                EnvFilter::try_new(directives).map_err(|e| TelemetryError::InvalidFilter(e.to_string()))
            }
            None => Ok(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))),
        }
    }

    fn redactor(&self) -> Redactor {
        Redactor::with_extra_deny_names(&self.extra_redacted_fields)
    }
}

/// Keeps telemetry resources alive; drop it at process exit to flush exporters.
#[derive(Debug)]
#[must_use = "dropping the guard stops OTLP export"]
pub struct TelemetryGuard {
    _otlp: Option<otlp::OtlpHandle>,
}

/// Build the subscriber stack (filter, trace-id layer, redaction layer, redacting `fmt`
/// layer) writing to `writer`, without installing it.
///
/// # Errors
/// [`TelemetryError::InvalidFilter`] when the filter directives do not parse.
pub fn build_subscriber<W>(
    config: &TelemetryConfig,
    writer: W,
) -> Result<impl Subscriber + for<'a> LookupSpan<'a> + Send + Sync, TelemetryError>
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let filter = config.env_filter()?;
    let redactor = config.redactor();
    let fmt_layer = tracing_subscriber::fmt::layer()
        .event_format(RedactingFormat::new(config.format, redactor.clone()))
        .fmt_fields(format::DiscardFields)
        .with_ansi(false)
        .with_writer(writer);
    Ok(tracing_subscriber::registry()
        .with(filter)
        .with(TraceIdLayer::new())
        .with(RedactionLayer::new(redactor))
        .with(fmt_layer))
}

/// Install the global subscriber.
///
/// With the `otlp` feature and an endpoint configured, call this from inside a
/// Tokio runtime: the gRPC exporter binds to the ambient runtime.
///
/// # Errors
/// [`TelemetryError::InvalidFilter`], [`TelemetryError::AlreadyInitialized`],
/// or an OTLP error when the `otlp` feature is enabled (see [`otlp`]).
pub fn init(config: TelemetryConfig) -> Result<TelemetryGuard, TelemetryError> {
    let otlp_handle = match &config.otlp {
        Some(cfg) => otlp::install(cfg)?,
        None => None,
    };
    let subscriber = match config.output {
        LogOutput::Stderr => {
            with_otlp(build_subscriber(&config, std::io::stderr)?, otlp_handle.as_ref()).try_init()
        }
        LogOutput::Stdout => {
            with_otlp(build_subscriber(&config, std::io::stdout)?, otlp_handle.as_ref()).try_init()
        }
    };
    subscriber.map_err(|_| TelemetryError::AlreadyInitialized)?;
    if config.otlp.is_some() && !otlp::enabled() {
        tracing::warn!("OTLP endpoint configured but this build has no `otlp` feature; export is disabled");
    }
    Ok(TelemetryGuard { _otlp: otlp_handle })
}

/// Add the OTLP span layer (feature `otlp`) to a built subscriber.
#[cfg(feature = "otlp")]
fn with_otlp<S>(subscriber: S, handle: Option<&otlp::OtlpHandle>) -> impl Subscriber + Send + Sync + 'static
where
    S: Subscriber + for<'a> LookupSpan<'a> + Send + Sync + 'static,
{
    subscriber.with(handle.map(otlp::OtlpHandle::layer))
}

/// No OTLP layer without the feature: the subscriber passes through unchanged.
#[cfg(not(feature = "otlp"))]
fn with_otlp<S>(subscriber: S, _handle: Option<&otlp::OtlpHandle>) -> impl Subscriber + Send + Sync + 'static
where
    S: Subscriber + for<'a> LookupSpan<'a> + Send + Sync + 'static,
{
    subscriber
}
