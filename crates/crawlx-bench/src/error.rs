//! Error type of the benchmark crate.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Everything that can fail in `crawlx-bench`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BenchError {
    /// The gym could not bind its listen address.
    #[error("gym server could not bind {addr}")]
    Bind {
        /// The address that was requested.
        addr: SocketAddr,
        /// The socket error.
        #[source]
        source: std::io::Error,
    },
    /// The gym is running but its bound address could not be read.
    #[error("gym server address unavailable")]
    LocalAddr(#[source] std::io::Error),
    /// A fixture id is not part of the catalog.
    #[error("unknown fixture `{0}`")]
    UnknownFixture(String),
    /// A manifest or trace did not validate.
    #[error("manifest `{what}`: {reason}")]
    Manifest {
        /// The manifest id or file.
        what: String,
        /// The first violated rule.
        reason: String,
    },
    /// JSON encode/decode.
    #[error("json")]
    Json(#[from] serde_json::Error),
    /// File system access.
    #[error("i/o on {path}")]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// An oracle result file was malformed or refused (mixed drivers).
    #[error("oracle: {0}")]
    Oracle(String),
    /// A replay trace could not be replayed.
    #[error("replay: {0}")]
    Replay(String),
    /// An ablation variant could not be executed.
    #[error("ablation: {0}")]
    Ablation(String),
    /// A benchmark statistic could not be computed.
    #[error("statistics")]
    Stats(#[from] crate::stats::StatsError),
    /// A URL did not parse.
    #[error("url")]
    Url(#[from] url::ParseError),
    /// A URL failed canonicalization or a sitemap failed to parse.
    #[error("url plane")]
    UrlPlane(#[from] crawlx_url::UrlError),
    /// The fetch plane failed.
    #[error("fetch")]
    Fetch(#[from] crawlx_fetch::FetchError),
    /// A policy (scope, robots) could not be built.
    #[error("policy")]
    Policy(#[from] crawlx_policy::PolicyError),
    /// An element identity could not be hashed.
    #[error("element identity")]
    Elements(#[from] crawlx_elements::ElementsError),
    /// A network literal did not parse.
    #[error("network literal")]
    Network(#[from] ipnet::AddrParseError),
    /// Browser plane failure.
    #[error("browser")]
    Browser(#[from] crawlx_core::browser::BrowserError),
    /// Repository failure while loading run rows.
    #[error("store")]
    Store(#[from] crawlx_core::error::StoreError),
    /// The worker run failed.
    #[error("worker")]
    Worker(#[from] crawlx_worker::WorkerError),
    /// A controlled fixture capability could not be created or validated.
    #[error("fixture evaluation")]
    FixtureEvaluation(#[from] crawlx_worker::fixture_evaluation::FixtureEvaluationError),
    /// The trail verifier could not load or decode a row.
    #[error("trail: {0}")]
    Trail(String),
    /// A milestone gate did not pass; carries the failed criteria.
    #[error("gate: {0}")]
    Gate(String),
    /// A `crawl-bench` target, profile, metric, baseline or recorder is unusable; the message
    /// names the offending input.
    #[error("{0}")]
    CrawlBench(String),
    /// An upstream crawl request given to the differential runner is malformed.
    #[error("differential request: {0}")]
    Request(String),
}

impl BenchError {
    pub(crate) fn manifest(what: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Manifest {
            what: what.into(),
            reason: reason.into(),
        }
    }

    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// `error: cause: cause` through every `source()`, for binaries that print one line.
    /// The variant messages are deliberately short (`err-source-chain`); without the chain a
    /// bench log says only `worker`.
    #[must_use]
    pub fn chain(&self) -> String {
        chain(self)
    }
}

/// `error: cause: cause` for any error and its sources.
#[must_use]
pub fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}
