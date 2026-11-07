//! The deployment lists feed.
//!
//! [`EgressListSource`] says where the two deployment lists come from: the static values of
//! `crawlx.toml` (`egress.deployment_allowlist`, `egress.operator_blocklist`) and, optionally, a
//! file per list (`egress.deployment_allowlist_file`, `egress.operator_blocklist_file`; the
//! environment variables `CRAWLX_EGRESS_DEPLOYMENT_ALLOWLIST_FILE` and
//! `CRAWLX_EGRESS_OPERATOR_BLOCKLIST_FILE` name the same files). **A set file replaces the static
//! list of its kind**: the allowlist file is the whole allowlist (an empty file means "no private
//! network is reachable"), the blocklist file is the whole blocklist. A file that is named but
//! missing, unreadable or malformed is an error, never an empty list.
//!
//! [`ListReloader`] owns the live [`SharedEgressLists`] every [`crawlx_policy::EgressPolicy`]
//! holds. It re-reads the files on `SIGHUP` (unix) and on a poll every 60 seconds (the interval
//! is configurable), publishing a new snapshot when a file changed: modification time, length or
//! content hash differ. A file that no longer parses keeps the previous snapshot in force and
//! logs a `warn` naming the list, the path and the line number, never the entry; the warning is
//! repeated only when the failure changes. Runs already in flight see the new lists on their
//! next connection.

use crawlx_policy::{EgressLists, ListError, SharedEgressLists};
use ipnet::IpNet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::AsyncReadExt as _;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// How often [`ListReloader::spawn`] polls the files by default.
pub const DEFAULT_RELOAD_INTERVAL: Duration = Duration::from_secs(60);

/// Which of the two deployment lists.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ListKind {
    /// `egress.deployment_allowlist`: the private networks the deployment lets runs reach.
    DeploymentAllowlist,
    /// `egress.operator_blocklist`: hosts, addresses and networks no run may reach.
    OperatorBlocklist,
}

impl ListKind {
    /// The configuration key without its section (`deployment_allowlist`, `operator_blocklist`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeploymentAllowlist => "deployment_allowlist",
            Self::OperatorBlocklist => "operator_blocklist",
        }
    }
}

impl fmt::Display for ListKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A list that could not be built. The previous snapshot stays in force on reload.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ListsError {
    /// The named file cannot be read (missing, unreadable, not UTF-8).
    #[error("{list} file {}: {source}", path.display())]
    Read {
        /// Which list the file feeds.
        list: ListKind,
        /// The configured path.
        path: PathBuf,
        /// The I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A line of the named file is not a valid entry.
    #[error("{list} file {}: {source}", path.display())]
    Parse {
        /// Which list the file feeds.
        list: ListKind,
        /// The configured path.
        path: PathBuf,
        /// The offending line (1-based) and entry.
        #[source]
        source: ListError,
    },
    /// An entry of the static configuration is not valid.
    #[error("{list}: {source}")]
    Static {
        /// Which list the entry belongs to.
        list: ListKind,
        /// The offending entry.
        #[source]
        source: ListError,
    },
}

impl ListsError {
    /// Which list failed.
    #[must_use]
    pub const fn list(&self) -> ListKind {
        match self {
            Self::Read { list, .. } | Self::Parse { list, .. } | Self::Static { list, .. } => *list,
        }
    }

    /// The file, when the failure is about one.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Read { path, .. } | Self::Parse { path, .. } => Some(path),
            Self::Static { .. } => None,
        }
    }

    /// The 1-based line of the offending entry in the file, when known.
    #[must_use]
    pub fn line(&self) -> Option<usize> {
        match self {
            Self::Parse { source, .. } | Self::Static { source, .. } => match source {
                ListError::Network { line, .. } | ListError::Host { line, .. } => {
                    Some(*line).filter(|l| *l > 0)
                }
                _ => None,
            },
            Self::Read { .. } => None,
        }
    }

    /// A fixed phrase for logs: never carries an entry or file content.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Read { .. } => "file unreadable",
            Self::Parse { source, .. } | Self::Static { source, .. } => match source {
                ListError::Network { .. } => "invalid network entry",
                ListError::Host { .. } => "invalid host entry",
                _ => "invalid entry",
            },
        }
    }
}

/// Where the deployment lists come from.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct EgressListSource {
    /// `egress.deployment_allowlist`; `None` = the deployment sets no bound. Ignored while
    /// [`Self::allowlist_file`] is set.
    pub allowlist_static: Option<Vec<IpNet>>,
    /// `egress.operator_blocklist`: host, `*.host`, IP address or CIDR entries. Ignored while
    /// [`Self::blocklist_file`] is set.
    pub blocklist_static: Vec<String>,
    /// File with one CIDR or IP address per line (`#` comments); replaces the static allowlist.
    pub allowlist_file: Option<PathBuf>,
    /// File with one host, `*.host`, IP address or CIDR per line (`#` comments); replaces the
    /// static blocklist.
    pub blocklist_file: Option<PathBuf>,
}

/// Content and change stamp of one file at one read.
#[derive(Clone, PartialEq, Eq, Debug)]
struct FileStamp {
    modified: Option<SystemTime>,
    len: u64,
    digest: blake3::Hash,
}

struct FileText {
    text: String,
    stamp: FileStamp,
}

/// Both files as read at one instant.
#[derive(Default)]
struct Snapshot {
    allow: Option<FileText>,
    block: Option<FileText>,
}

/// What the files looked like when the lists in force were built.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
struct Stamps {
    allow: Option<FileStamp>,
    block: Option<FileStamp>,
}

impl Snapshot {
    fn stamps(&self) -> Stamps {
        Stamps {
            allow: self.allow.as_ref().map(|f| f.stamp.clone()),
            block: self.block.as_ref().map(|f| f.stamp.clone()),
        }
    }
}

fn utf8(list: ListKind, path: &Path, bytes: Vec<u8>) -> Result<String, ListsError> {
    String::from_utf8(bytes).map_err(|_| ListsError::Read {
        list,
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, "the file is not valid UTF-8"),
    })
}

fn read_error(list: ListKind, path: &Path, source: std::io::Error) -> ListsError {
    ListsError::Read {
        list,
        path: path.to_path_buf(),
        source,
    }
}

async fn read_file(list: ListKind, path: &Path) -> Result<FileText, ListsError> {
    let fail = |e| read_error(list, path, e);
    let mut file = tokio::fs::File::open(path).await.map_err(fail)?;
    let meta = file.metadata().await.map_err(fail)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).await.map_err(fail)?;
    let stamp = FileStamp {
        modified: meta.modified().ok(),
        len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        digest: blake3::hash(&bytes),
    };
    Ok(FileText {
        text: utf8(list, path, bytes)?,
        stamp,
    })
}

fn read_file_blocking(list: ListKind, path: &Path) -> Result<FileText, ListsError> {
    use std::io::Read as _;
    let fail = |e| read_error(list, path, e);
    let mut file = std::fs::File::open(path).map_err(fail)?;
    let meta = file.metadata().map_err(fail)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(fail)?;
    let stamp = FileStamp {
        modified: meta.modified().ok(),
        len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        digest: blake3::hash(&bytes),
    };
    Ok(FileText {
        text: utf8(list, path, bytes)?,
        stamp,
    })
}

impl EgressListSource {
    /// Does either list come from a file (and so can change at run time)?
    #[must_use]
    pub fn has_files(&self) -> bool {
        self.allowlist_file.is_some() || self.blocklist_file.is_some()
    }

    /// Read the files and build the lists in force. A set file replaces the static list of its
    /// kind.
    ///
    /// # Errors
    /// [`ListsError`] when a named file cannot be read or a line of it, or a static entry, is not
    /// a valid network or host.
    pub async fn load(&self) -> Result<EgressLists, ListsError> {
        self.build(&self.read().await?)
    }

    /// [`Self::load`] for synchronous callers (`crawlx config check`).
    ///
    /// # Errors
    /// See [`Self::load`].
    pub fn load_blocking(&self) -> Result<EgressLists, ListsError> {
        let allow = self
            .allowlist_file
            .as_deref()
            .map(|p| read_file_blocking(ListKind::DeploymentAllowlist, p))
            .transpose()?;
        let block = self
            .blocklist_file
            .as_deref()
            .map(|p| read_file_blocking(ListKind::OperatorBlocklist, p))
            .transpose()?;
        self.build(&Snapshot { allow, block })
    }

    async fn read(&self) -> Result<Snapshot, ListsError> {
        let allow = match &self.allowlist_file {
            Some(path) => Some(read_file(ListKind::DeploymentAllowlist, path).await?),
            None => None,
        };
        let block = match &self.blocklist_file {
            Some(path) => Some(read_file(ListKind::OperatorBlocklist, path).await?),
            None => None,
        };
        Ok(Snapshot { allow, block })
    }

    fn build(&self, read: &Snapshot) -> Result<EgressLists, ListsError> {
        let allowlist =
            match (&read.allow, &self.allowlist_file) {
                (Some(file), Some(path)) => Some(EgressLists::parse_allowlist(&file.text).map_err(
                    |source| ListsError::Parse {
                        list: ListKind::DeploymentAllowlist,
                        path: path.clone(),
                        source,
                    },
                )?),
                _ => self.allowlist_static.clone(),
            };
        let entries = match (&read.block, &self.blocklist_file) {
            (Some(file), Some(path)) => {
                EgressLists::parse_blocklist(&file.text).map_err(|source| ListsError::Parse {
                    list: ListKind::OperatorBlocklist,
                    path: path.clone(),
                    source,
                })?
            }
            _ => self.blocklist_static.clone(),
        };
        EgressLists::new(allowlist, entries).map_err(|source| ListsError::Static {
            list: ListKind::OperatorBlocklist,
            source,
        })
    }
}

/// Did a poll publish new lists?
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Reload {
    /// Neither file changed since the lists in force were built.
    Unchanged,
    /// New lists were published to every holder of the handle.
    Applied,
}

#[derive(Debug)]
struct ReloadState {
    /// The files as they were when the lists in force were built.
    stamps: Stamps,
    /// The failure last warned about; a repeat of it is not warned about again.
    failure: Option<String>,
}

/// Keeps the live lists in step with their files; see the module documentation.
#[derive(Debug)]
pub struct ListReloader {
    source: EgressListSource,
    lists: SharedEgressLists,
    interval: Duration,
    state: tokio::sync::Mutex<ReloadState>,
}

impl ListReloader {
    /// Build the first snapshot from `source` and start owning its handle.
    ///
    /// # Errors
    /// [`ListsError`] when the lists cannot be built: a deployment must not start with lists it
    /// cannot read.
    pub async fn open(source: EgressListSource) -> Result<Self, ListsError> {
        let read = source.read().await?;
        let lists = source.build(&read)?;
        Ok(Self {
            state: tokio::sync::Mutex::new(ReloadState {
                stamps: read.stamps(),
                failure: None,
            }),
            lists: SharedEgressLists::new(lists),
            interval: DEFAULT_RELOAD_INTERVAL,
            source,
        })
    }

    /// Poll the files every `interval` instead of every [`DEFAULT_RELOAD_INTERVAL`].
    #[must_use]
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval.max(Duration::from_millis(1));
        self
    }

    /// The live lists: hand clones of this to every policy.
    #[must_use]
    pub fn lists(&self) -> SharedEgressLists {
        self.lists.clone()
    }

    /// Where the lists come from.
    #[must_use]
    pub fn source(&self) -> &EgressListSource {
        &self.source
    }

    /// Re-read the files and publish the result whether or not they changed (the `SIGHUP`
    /// action).
    ///
    /// # Errors
    /// [`ListsError`] when the files no longer yield lists; the previous lists stay in force and
    /// a warning is logged.
    pub async fn reload_now(&self) -> Result<(), ListsError> {
        self.refresh(true).await.map(drop)
    }

    /// Re-read the files and publish new lists only when one of them changed (the poll action).
    ///
    /// # Errors
    /// See [`Self::reload_now`].
    pub async fn poll_once(&self) -> Result<Reload, ListsError> {
        self.refresh(false).await
    }

    async fn refresh(&self, force: bool) -> Result<Reload, ListsError> {
        // serialises SIGHUP, the poll and explicit calls; a tokio mutex, held across the reads
        let mut state = self.state.lock().await;
        let built = match self.source.read().await {
            Ok(read) => {
                let stamps = read.stamps();
                if !force && state.failure.is_none() && stamps == state.stamps {
                    return Ok(Reload::Unchanged);
                }
                self.source.build(&read).map(|lists| (lists, stamps))
            }
            Err(e) => Err(e),
        };
        match built {
            Ok((lists, stamps)) => {
                tracing::info!(
                    allowlist_networks = lists.allowlist().map(<[IpNet]>::len),
                    blocklist_entries = lists.blocklist_entries().len(),
                    "egress lists reloaded"
                );
                self.lists.replace(lists);
                state.stamps = stamps;
                state.failure = None;
                Ok(Reload::Applied)
            }
            Err(e) => {
                let key = format!("{}|{:?}|{:?}|{}", e.list(), e.path(), e.line(), e.reason());
                if force || state.failure.as_deref() != Some(key.as_str()) {
                    tracing::warn!(
                        list = e.list().as_str(),
                        path = %e.path().map_or_else(String::new, |p| p.display().to_string()),
                        line = e.line(),
                        reason = e.reason(),
                        "egress list reload failed; keeping the previous lists"
                    );
                }
                state.failure = Some(key);
                Err(e)
            }
        }
    }

    /// Start the reload task: it polls every interval, reloads on `SIGHUP` (unix) and ends when
    /// `cancel` fires. The signal handler is installed before this returns.
    #[must_use = "await the handle after cancelling to wait for the task to end"]
    pub fn spawn(self: &Arc<Self>, cancel: CancellationToken) -> JoinHandle<()> {
        let this = Arc::clone(self);
        let hangup = Hangup::install();
        tokio::spawn(async move { this.run(cancel, hangup).await })
    }

    async fn run(self: Arc<Self>, cancel: CancellationToken, mut hangup: Hangup) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // the first tick completes at once and the lists were just built
        ticker.tick().await;
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    // failures are logged by `refresh`; the previous lists stay in force
                    drop(self.poll_once().await);
                }
                () = hangup.recv() => {
                    tracing::info!("SIGHUP: reloading the egress lists");
                    drop(self.reload_now().await);
                }
            }
        }
    }
}

/// The `SIGHUP` stream (unix); never fires elsewhere.
#[cfg(unix)]
struct Hangup(Option<tokio::signal::unix::Signal>);

#[cfg(unix)]
impl Hangup {
    fn install() -> Self {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(signal) => Self(Some(signal)),
            Err(e) => {
                tracing::warn!(error = %e, "SIGHUP handler not installed; the egress lists reload on the poll only");
                Self(None)
            }
        }
    }

    async fn recv(&mut self) {
        if let Some(signal) = &mut self.0 {
            if signal.recv().await.is_some() {
                return;
            }
            self.0 = None;
        }
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
struct Hangup;

#[cfg(not(unix))]
impl Hangup {
    fn install() -> Self {
        Self
    }

    async fn recv(&mut self) {
        std::future::pending::<()>().await;
    }
}
