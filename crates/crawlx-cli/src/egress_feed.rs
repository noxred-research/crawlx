//! The egress lists of a running process (`serve`, `worker`, `crawl`).
//!
//! One [`SharedEgressLists`] is built from `crawlx.toml` and the environment
//! ([`crate::config_check::egress_source_from_env`]) and handed to every policy of the process
//! (`ApiConfig.egress_lists`, `WorkerConfig.egress.lists`, `AdmissionPolicy::with_egress_lists`).
//! When a list comes from a file, a [`ListReloader`] keeps it current (SIGHUP and a 60 s poll)
//! until the feed is stopped or dropped.

use anyhow::Context as _;
use crawlx_fetch::lists::ListReloader;
use crawlx_policy::SharedEgressLists;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// The live lists and the task that reloads them.
pub(crate) struct EgressFeed {
    lists: SharedEgressLists,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl EgressFeed {
    /// Build the lists and, when a file feeds one of them, start the reload task.
    ///
    /// # Errors
    /// Fails when the configuration cannot be read or a list cannot be built: a process must not
    /// start with lists it cannot read.
    pub(crate) async fn start(getenv: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let source = crate::config_check::egress_source_from_env(getenv)?;
        let reloader = Arc::new(ListReloader::open(source).await.context("egress lists")?);
        let stop = CancellationToken::new();
        let task = reloader
            .source()
            .has_files()
            .then(|| reloader.spawn(stop.clone()));
        Ok(Self {
            lists: reloader.lists(),
            stop,
            task,
        })
    }

    /// The handle every policy of the process holds.
    pub(crate) fn lists(&self) -> SharedEgressLists {
        self.lists.clone()
    }

    /// Stop the reload task and wait for it. Dropping the feed stops the task without waiting.
    pub(crate) async fn stop(mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            if let Err(e) = task.await {
                tracing::warn!(error = %e, "egress list reload task ended abnormally");
            }
        }
    }
}

impl Drop for EgressFeed {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
