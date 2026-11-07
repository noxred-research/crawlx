//! `Supervisor::spawn(name, fut)`: the only way the worker starts long-lived tasks.
//! A panic inside the task becomes a typed [`SessionFailure`] event
//! instead of a silently dead detached task.

use crawlx_core::SessionId;
use futures::FutureExt as _;
use std::any::Any;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::task::TaskTracker;
use tracing::Instrument as _;

/// A supervised task died.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[error("task {name} failed: {message}")]
#[non_exhaustive]
pub struct SessionFailure {
    /// The name given to [`Supervisor::spawn`].
    pub name: String,
    /// Session the task served, if any.
    pub session: Option<SessionId>,
    /// The panic payload when it was a string, else a generic message.
    pub message: String,
}

/// Handle of a supervised task: resolves to the task's output or its [`SessionFailure`].
pub type SupervisedTask<T> = JoinHandle<Result<T, SessionFailure>>;

/// Tracks every task it spawns and reports panics.
#[derive(Clone)]
pub struct Supervisor {
    tracker: TaskTracker,
    failures: broadcast::Sender<SessionFailure>,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "task panicked".to_owned())
}

impl Supervisor {
    #[must_use]
    /// New.
    pub fn new() -> Self {
        let (failures, _) = broadcast::channel(64);
        Self {
            tracker: TaskTracker::new(),
            failures,
        }
    }

    /// Receive failure events (lagging receivers lose the oldest events).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<SessionFailure> {
        self.failures.subscribe()
    }

    /// Spawn `fut` under `name`.
    pub fn spawn<T, F>(&self, name: &str, fut: F) -> SupervisedTask<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        self.spawn_for(name, None, fut)
    }

    /// Spawn `fut` serving `session`. The task runs inside the span current at the call, so
    /// its spans (and the journal rows written under them) stay in the spawner's trace
    /// (the span-to-row join). It also inherits the spawner's artifact producer scope
    /// ([`crawlx_core::custody::inherit`]): task-locals do not cross a spawn on their own.
    pub fn spawn_for<T, F>(&self, name: &str, session: Option<SessionId>, fut: F) -> SupervisedTask<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let name = name.to_owned();
        let failures = self.failures.clone();
        let span = tracing::Span::current();
        self.tracker.spawn(crawlx_core::custody::inherit(async move {
            // Heap-pin the task body: the actor future is large, and each wrapper above it (the
            // custody scope, the tracker, `catch_unwind`) would otherwise hold or move it by value
            // on the worker thread's stack, which overflows its 2 MiB in debug builds.
            match AssertUnwindSafe(Box::pin(fut)).catch_unwind().await {
                Ok(v) => Ok(v),
                Err(payload) => {
                    let failure = SessionFailure {
                        name,
                        session,
                        message: panic_message(payload.as_ref()),
                    };
                    tracing::error!(task = %failure.name, message = %failure.message, "supervised task panicked");
                    // no subscriber is a normal state
                    let _ = failures.send(failure.clone());
                    Err(failure)
                }
            }
        }).instrument(span))
    }

    /// Stop accepting tasks and wait for every spawned task to finish.
    pub async fn shutdown(&self) {
        self.tracker.close();
        self.tracker.wait().await;
    }

    /// Number of tasks still running.
    #[must_use]
    pub fn running(&self) -> usize {
        self.tracker.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[tokio::test]
    async fn panics_become_typed_failures() {
        let sup = Supervisor::new();
        let mut rx = sup.subscribe();
        let session = SessionId::new();
        let h = sup.spawn_for("boom", Some(session), async {
            if true {
                panic!("kaput");
            }
            7u8
        });
        let err = h.await.unwrap().unwrap_err();
        assert_eq!(err.name, "boom");
        assert_eq!(err.session, Some(session));
        assert_eq!(err.message, "kaput");
        assert_eq!(rx.recv().await.unwrap(), err);
    }

    #[tokio::test]
    async fn normal_tasks_return_their_output_and_shutdown_waits() {
        let sup = Supervisor::new();
        let h = sup.spawn("ok", async { 41 + 1 });
        assert_eq!(h.await.unwrap().unwrap(), 42);
        sup.shutdown().await;
        assert_eq!(sup.running(), 0);
    }
}
